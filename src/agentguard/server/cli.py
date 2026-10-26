"""``agentguard server ...`` commands."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os


def _cmd_run(ns: argparse.Namespace) -> int:
    import uvicorn

    from agentguard.server.app import create_app
    from agentguard.server.settings import get_settings

    settings = get_settings()
    if ns.migrate:
        from agentguard.server.migrations import upgrade

        upgrade(settings.database_url)
    uvicorn.run(
        create_app(settings, create_schema=False if ns.migrate else None),
        host=ns.host,
        port=ns.port,
        ssl_certfile=ns.ssl_certfile,
        ssl_keyfile=ns.ssl_keyfile,
        proxy_headers=settings.trust_proxy_headers,
        forwarded_allow_ips="*" if settings.trust_proxy_headers else None,
        server_header=False,
        log_level=os.environ.get("AGENTGUARD_LOG_LEVEL", "info"),
    )
    return 0


def _cmd_migrate(ns: argparse.Namespace) -> int:
    from agentguard.server.migrations import upgrade
    from agentguard.server.settings import get_settings

    upgrade(ns.database_url or get_settings().database_url, ns.revision)
    print("database migrated")
    return 0


def _cmd_create_admin(ns: argparse.Namespace) -> int:
    from sqlalchemy import select

    from agentguard.server import audit
    from agentguard.server.db import Database
    from agentguard.server.models import Membership, Organization, User
    from agentguard.server.security import hash_password
    from agentguard.server.settings import get_settings

    password = os.environ.get("AGENTGUARD_ADMIN_PASSWORD") or getpass.getpass("Password (min 12 chars): ")

    async def run() -> None:
        db = Database(get_settings().database_url)
        async with db.sessionmaker() as s:
            org = (await s.execute(select(Organization).where(Organization.slug == ns.org_slug))).scalar_one_or_none()
            if org is None:
                org = Organization(name=ns.org_name or ns.org_slug, slug=ns.org_slug, settings={})
                s.add(org)
                await s.flush()
            user = (await s.execute(select(User).where(User.email == ns.email.lower()))).scalar_one_or_none()
            if user is None:
                user = User(email=ns.email.lower(), name=ns.email.split("@")[0], password_hash=hash_password(password))
                s.add(user)
                await s.flush()
            s.add(Membership(org_id=org.id, user_id=user.id, role="admin"))
            await s.commit()
            await audit.append(s, org.id, "cli", "member.added", user.id, {"email": user.email, "role": "admin"})
        await db.dispose()

    asyncio.run(run())
    print(f"admin {ns.email} added to organization {ns.org_slug}")
    return 0


def _cmd_prune(ns: argparse.Namespace) -> int:
    from agentguard.server.db import Database
    from agentguard.server.services import prune_events
    from agentguard.server.settings import get_settings

    settings = get_settings()

    async def run() -> int:
        db = Database(settings.database_url)
        async with db.sessionmaker() as s:
            n = await prune_events(s, ns.days or settings.event_retention_days)
        await db.dispose()
        return n

    print(json.dumps({"deleted_events": asyncio.run(run())}))
    return 0


def _cmd_verify_audit(ns: argparse.Namespace) -> int:
    from agentguard.server import audit
    from agentguard.server.db import Database
    from agentguard.server.settings import get_settings

    async def run() -> dict[str, object]:
        db = Database(get_settings().database_url)
        async with db.sessionmaker() as s:
            out = await audit.verify(s, ns.org_id)
        await db.dispose()
        return out

    result = asyncio.run(run())
    print(json.dumps(result))
    return 0 if result["valid"] else 1


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    srv = sub.add_parser("server", help="control plane").add_subparsers(dest="server_cmd", required=True)
    r = srv.add_parser("run", help="run the control plane (API + dashboard)")
    r.add_argument("--host", default=os.environ.get("AGENTGUARD_HOST", "127.0.0.1"))
    r.add_argument("--port", type=int, default=int(os.environ.get("AGENTGUARD_PORT", "8000")))
    r.add_argument("--migrate", action="store_true", help="apply database migrations before starting")
    r.add_argument("--ssl-certfile", default=os.environ.get("AGENTGUARD_TLS_CERT"))
    r.add_argument("--ssl-keyfile", default=os.environ.get("AGENTGUARD_TLS_KEY"))
    r.set_defaults(func=_cmd_run)
    m = srv.add_parser("migrate", help="apply database migrations")
    m.add_argument("--database-url")
    m.add_argument("--revision", default="head")
    m.set_defaults(func=_cmd_migrate)
    a = srv.add_parser(
        "create-admin",
        help="create an organization admin (password from AGENTGUARD_ADMIN_PASSWORD or prompt)",
    )
    a.add_argument("email")
    a.add_argument("--org-slug", default="default")
    a.add_argument("--org-name")
    a.set_defaults(func=_cmd_create_admin)
    p = srv.add_parser("prune", help="delete events older than the retention period")
    p.add_argument("--days", type=int)
    p.set_defaults(func=_cmd_prune)
    v = srv.add_parser("verify-audit", help="verify an organization's audit hash chain")
    v.add_argument("org_id")
    v.set_defaults(func=_cmd_verify_audit)
