"""Render a static, read-only snapshot of the dashboard with demo data (for GitHub Pages).

    python scripts/static_demo.py site/demo

Boots the real control plane in-process on a temporary SQLite database, loads the demo sessions
(`agentguard.server.demo`), signs in, and saves every page as flat HTML. Links are rewritten to the
saved files; live polling and actions are disabled, and a banner says it is a snapshot.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import sys
import tempfile
from pathlib import Path

import httpx

from agentguard.core.ratelimit import MemoryRateLimiter
from agentguard.server.app import bootstrap, create_app
from agentguard.server.db import Database
from agentguard.server.demo import seed
from agentguard.server.settings import ServerSettings

EMAIL, PASSWORD = "demo@agentguard.dev", "static-demo-password"
BANNER = (
    '<div class="preview-banner">Static preview of the AgentGuard dashboard with demo data. Actions are '
    'disabled. <a href="https://github.com/Alexm2025/agentguard#control-plane">Run it yourself</a> for the live version.</div>'
)


def page_name(path: str) -> str:
    path, _, query = path.partition("?")
    parts = [p for p in path.strip("/").split("/") if p]
    if not parts:
        return "index.html"
    name = "-".join(parts)
    if query.startswith("action="):
        name += "-" + query.split("=", 1)[1]
    return f"{name}.html"


def rewrite(html: str) -> str:
    html = html.replace('<script src="/static/htmx.min.js" defer></script>', "")
    html = html.replace('href="/static/app.css"', 'href="app.css"')
    html = html.replace('<span class="live">Live</span>', "").replace("Refreshes every 3 seconds", "Snapshot")
    html = re.sub(r'\s(hx-[a-z-]+)=(\'[^\']*\'|"[^"]*")', "", html)

    def link(m: re.Match[str]) -> str:
        target = m.group(1)
        if target.startswith(("/api/", "/auth/")):
            return 'href="#"'
        return f'href="{page_name(target)}"'

    html = re.sub(r'href="(/[^"]*)"', link, html)
    html = re.sub(r"<(button|input)(?![^>]*type=\"hidden\")", r"<\1 disabled", html)
    html = re.sub(r'<form([^>]*)action="[^"]*"', r"<form\1", html)
    return _inject_banner(html)


def _inject_banner(html: str) -> str:
    m = re.search(r"<body[^>]*>", html)
    return html[: m.end()] + BANNER + html[m.end() :] if m else html


async def main(out: Path) -> None:
    tmp = Path(tempfile.mkdtemp())
    settings = ServerSettings(
        env="development",
        database_url=f"sqlite+aiosqlite:///{(tmp / 'demo.db').as_posix()}",
        secret_key="static-demo-secret-key-0123456789abcdef",
        bootstrap_admin_email=EMAIL,
        bootstrap_admin_password=PASSWORD,
        public_url="http://demo.local",
    )
    db = Database(settings.database_url)
    await db.create_all()
    await bootstrap(db, settings)
    await seed(settings)
    app = create_app(settings, database=db, create_schema=False, rate_limiter=MemoryRateLimiter())
    out.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://demo.local") as c:
        login = await c.get("/login")
        (out / "login.html").write_text(rewrite(login.text), encoding="utf-8")
        token = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)  # type: ignore[union-attr]
        r = await c.post("/login", data={"email": EMAIL, "password": PASSWORD, "csrf_token": token})
        assert r.status_code == 303, r.text
        todo = ["/events", "/approvals", "/policies", "/metrics", "/settings"]
        todo += [f"/events?action={a}" for a in ("BLOCK", "REQUIRE_APPROVAL", "REDACT", "ALLOW")]
        seen: set[str] = set()
        while todo:
            path = todo.pop(0)
            name = page_name(path)
            if name in seen:
                continue
            seen.add(name)
            resp = await c.get(path)
            if resp.status_code != 200:
                continue
            html = resp.text
            for target in re.findall(r'href="(/(?:events|approvals|policies)/[^"?]+)"', html):
                if not target.endswith(("/new", "/feed")):
                    todo.append(target)
            (out / name).write_text(rewrite(html), encoding="utf-8")
        shutil.copy(out / "events.html", out / "index.html")
    static = Path(__file__).resolve().parents[1] / "src" / "agentguard" / "server" / "dashboard" / "static" / "app.css"
    shutil.copy(static, out / "app.css")
    await db.dispose()
    print(f"wrote {len(list(out.glob('*.html')))} pages to {out}")


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1] if len(sys.argv) > 1 else "site/demo")))
