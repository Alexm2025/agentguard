"""Public pages and self-service accounts: landing, sign-up, email verification, password reset,
account settings and onboarding."""

from __future__ import annotations

import hmac
import re
import secrets
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.server import audit, mailer
from agentguard.server.api.routes import set_session_cookie
from agentguard.server.auth import SESSION_COOKIE, Principal, _client_ip, create_session, get_db, resolve_principal
from agentguard.server.dashboard.views import LOGIN_CSRF, render, ui_principal
from agentguard.server.models import ApiKey, Event, Membership, Organization, User, WebSession, utcnow
from agentguard.server.security import generate_api_key, hash_password, sha256, sign, unsign, verify_password

router = APIRouter(include_in_schema=False)
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def _check_form_token(request: Request, token: str) -> None:
    cookie = request.cookies.get(LOGIN_CSRF, "")
    if not cookie or not hmac.compare_digest(cookie, token):
        raise HTTPException(status_code=403, detail="This form expired. Reload the page and try again.")


def _public(request: Request, name: str, **ctx: Any) -> Response:
    token = secrets.token_urlsafe(24)
    resp = render(
        request,
        name,
        None,
        csrf=token,
        signup=request.app.state.settings.allow_signup,
        sso=request.app.state.features.get("oidc"),
        **ctx,
    )
    resp.set_cookie(
        LOGIN_CSRF,
        token,
        httponly=True,
        samesite="strict",
        secure=request.app.state.settings.secure_cookies,
        max_age=1800,
    )
    return resp


async def _slug(db: AsyncSession, name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "team"
    slug = base
    while (await db.execute(select(Organization).where(Organization.slug == slug))).scalar_one_or_none():
        slug = f"{base}-{secrets.token_hex(3)}"
    return slug


def _reset_fingerprint(user: User) -> str:
    return sha256(user.password_hash or "none")[:16]


# ---------------------------------------------------------------- landing


@router.get("/")
async def landing(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    if request.cookies.get(SESSION_COOKIE):
        p = await resolve_principal(request, db)
        if p is not None and p.kind == "user":
            return RedirectResponse("/events", status_code=303)
    return render(request, "landing.html", None, signup=request.app.state.settings.allow_signup)


# ---------------------------------------------------------------- sign-up and verification


@router.get("/signup")
async def signup_form(request: Request) -> Response:
    if not request.app.state.settings.allow_signup:
        raise HTTPException(status_code=404, detail="Sign-up is disabled on this server.")
    return _public(request, "signup.html", error=None, values={})


@router.post("/signup")
async def signup_submit(
    request: Request,
    name: str = Form(min_length=1, max_length=200),
    email: str = Form(max_length=320),
    password: str = Form(max_length=1024),
    organization: str = Form(min_length=1, max_length=200),
    csrf_token: str = Form(max_length=100),
    db: AsyncSession = Depends(get_db),
) -> Response:
    settings = request.app.state.settings
    if not settings.allow_signup:
        raise HTTPException(status_code=404, detail="Sign-up is disabled on this server.")
    _check_form_token(request, csrf_token)
    values = {"name": name, "email": email, "organization": organization}
    email = email.strip().lower()
    if not request.app.state.rate_limiter.hit(f"signup:{_client_ip(request, settings)}", 5, 3600):
        return _public(
            request, "signup.html", error="Too many sign-ups from your network. Try again later.", values=values
        )
    if not EMAIL_RE.match(email):
        return _public(request, "signup.html", error="Enter a valid email address.", values=values)
    if len(password) < 12:
        return _public(request, "signup.html", error="Use a password with at least 12 characters.", values=values)
    if (await db.execute(select(User).where(User.email == email))).scalar_one_or_none():
        return _public(
            request, "signup.html", error="An account with this email already exists. Sign in instead.", values=values
        )

    verify = settings.email_enabled
    org = Organization(name=organization.strip(), slug=await _slug(db, organization), settings={})
    user = User(
        email=email,
        name=name.strip(),
        password_hash=hash_password(password),
        is_active=not verify,
        email_verified_at=None if verify else utcnow(),
    )
    db.add_all([org, user])
    await db.flush()
    db.add(Membership(org_id=org.id, user_id=user.id, role="admin"))
    await db.commit()
    await audit.append(db, org.id, f"user:{email}", "account.signup", user.id, {"organization": org.slug})

    if verify:
        token = sign({"p": "verify", "u": user.id}, settings.secret_key, 2 * 24 * 3600)
        link = f"{settings.public_url.rstrip('/')}/verify?token={token}"
        await mailer.send(
            settings,
            email,
            "Confirm your AgentGuard account",
            f"Hi {user.name or email},\n\nConfirm your email to activate your AgentGuard account:\n\n{link}\n\n"
            "The link is valid for 48 hours. If you did not sign up, ignore this email.\n",
        )
        return _public(
            request,
            "notice.html",
            title="Check your email",
            message=f"We sent a confirmation link to {email}. Open it to activate your account.",
        )
    token, _ = await create_session(db, user, org.id, request, settings)
    resp = RedirectResponse("/welcome", status_code=303)
    set_session_cookie(resp, token, settings)
    return resp


@router.get("/verify")
async def verify_email(request: Request, token: str = "", db: AsyncSession = Depends(get_db)) -> Response:
    claims = unsign(token, request.app.state.settings.secret_key)
    user = await db.get(User, str(claims.get("u"))) if claims and claims.get("p") == "verify" else None
    if user is None:
        return _public(
            request,
            "notice.html",
            title="Link expired",
            message="This confirmation link is invalid or has expired. Sign up again or contact your administrator.",
        )
    if user.email_verified_at is None:
        user.email_verified_at = utcnow()
        user.is_active = True
        await db.commit()
    mem = (await db.execute(select(Membership).where(Membership.user_id == user.id))).scalars().first()
    if mem is None:
        return RedirectResponse("/login", status_code=303)
    await audit.append(db, mem.org_id, f"user:{user.email}", "account.email_verified", user.id, {})
    session, _ = await create_session(db, user, mem.org_id, request, request.app.state.settings)
    resp = RedirectResponse("/welcome", status_code=303)
    set_session_cookie(resp, session, request.app.state.settings)
    return resp


# ---------------------------------------------------------------- password reset


@router.get("/forgot")
async def forgot_form(request: Request) -> Response:
    return _public(request, "forgot.html", sent=False, email_enabled=request.app.state.settings.email_enabled)


@router.post("/forgot")
async def forgot_submit(
    request: Request,
    email: str = Form(max_length=320),
    csrf_token: str = Form(max_length=100),
    db: AsyncSession = Depends(get_db),
) -> Response:
    settings = request.app.state.settings
    _check_form_token(request, csrf_token)
    email = email.strip().lower()
    ip = _client_ip(request, settings)
    if settings.email_enabled and request.app.state.rate_limiter.hit(f"forgot:{ip}:{email}", 3, 3600):
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user is not None and user.is_active and user.password_hash:
            token = sign({"p": "reset", "u": user.id, "h": _reset_fingerprint(user)}, settings.secret_key, 3600)
            link = f"{settings.public_url.rstrip('/')}/reset?token={token}"
            await mailer.send(
                settings,
                email,
                "Reset your AgentGuard password",
                f"Reset your AgentGuard password here (valid for 1 hour):\n\n{link}\n\n"
                "If you did not ask for this, ignore this email; your password is unchanged.\n",
            )
    # Same response whether or not the account exists.
    return _public(request, "forgot.html", sent=True, email_enabled=settings.email_enabled)


async def _reset_user(request: Request, db: AsyncSession, token: str) -> User | None:
    claims = unsign(token, request.app.state.settings.secret_key)
    if not claims or claims.get("p") != "reset":
        return None
    user = await db.get(User, str(claims.get("u")))
    if user is None or not hmac.compare_digest(str(claims.get("h")), _reset_fingerprint(user)):
        return None  # already used: the password (and so the fingerprint) changed
    return user


@router.get("/reset")
async def reset_form(request: Request, token: str = "", db: AsyncSession = Depends(get_db)) -> Response:
    if await _reset_user(request, db, token) is None:
        return _public(
            request, "notice.html", title="Link expired", message="This reset link is invalid, used or expired."
        )
    return _public(request, "reset.html", token=token, error=None)


@router.post("/reset")
async def reset_submit(
    request: Request,
    token: str = Form(max_length=2000),
    password: str = Form(max_length=1024),
    csrf_token: str = Form(max_length=100),
    db: AsyncSession = Depends(get_db),
) -> Response:
    _check_form_token(request, csrf_token)
    user = await _reset_user(request, db, token)
    if user is None:
        return _public(
            request, "notice.html", title="Link expired", message="This reset link is invalid, used or expired."
        )
    if len(password) < 12:
        return _public(request, "reset.html", token=token, error="Use a password with at least 12 characters.")
    user.password_hash = hash_password(password)
    await db.execute(delete(WebSession).where(WebSession.user_id == user.id))  # sign out everywhere
    await db.commit()
    for mem in (await db.execute(select(Membership).where(Membership.user_id == user.id))).scalars():
        await audit.append(db, mem.org_id, f"user:{user.email}", "account.password_reset", user.id, {})
    return _public(
        request,
        "notice.html",
        title="Password updated",
        message="Your password was changed. Sign in with the new one.",
        action=("/login", "Sign in"),
    )


# ---------------------------------------------------------------- account


@router.get("/account")
async def account_page(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    user = await db.get(User, p.id)
    org = await db.get(Organization, p.org_id)
    sessions = int(
        (await db.execute(select(func.count()).select_from(WebSession).where(WebSession.user_id == p.id))).scalar() or 0
    )
    return render(request, "account.html", p, user=user, org=org, sessions=sessions, message=None, error=None)


@router.post("/account/password")
async def account_password(
    request: Request,
    current: str = Form(max_length=1024),
    new: str = Form(max_length=1024),
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await db.get(User, p.id)
    org = await db.get(Organization, p.org_id)
    if user is None or org is None:
        raise HTTPException(status_code=404, detail="account not found")
    error = message = None
    if not verify_password(current, user.password_hash):
        error = "Your current password is incorrect."
    elif len(new) < 12:
        error = "Use a new password with at least 12 characters."
    else:
        user.password_hash = hash_password(new)
        keep = sha256(request.cookies.get(SESSION_COOKIE, ""))
        await db.execute(delete(WebSession).where(WebSession.user_id == user.id, WebSession.id != keep))
        await db.commit()
        await audit.append(db, p.org_id, p.actor, "account.password_changed", user.id, {})
        message = "Password changed. Other sessions were signed out."
    sessions = int(
        (await db.execute(select(func.count()).select_from(WebSession).where(WebSession.user_id == p.id))).scalar() or 0
    )
    return render(request, "account.html", p, user=user, org=org, sessions=sessions, message=message, error=error)


# ---------------------------------------------------------------- onboarding


async def _welcome(request: Request, p: Principal, db: AsyncSession, new_key: str | None = None) -> Response:
    org = await db.get(Organization, p.org_id)
    has_key = bool(
        (
            await db.execute(
                select(func.count()).select_from(ApiKey).where(ApiKey.org_id == p.org_id, ApiKey.revoked_at.is_(None))
            )
        ).scalar()
    )
    has_events = bool(
        (await db.execute(select(func.count()).select_from(Event).where(Event.org_id == p.org_id))).scalar()
    )
    return render(
        request,
        "welcome.html",
        p,
        org=org,
        has_key=has_key,
        has_events=has_events,
        new_key=new_key,
        base_url=request.app.state.settings.public_url.rstrip("/"),
    )


@router.get("/welcome")
async def welcome(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    return await _welcome(request, p, db)


@router.post("/welcome/key")
async def welcome_key(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    if not p.can("keys:manage"):
        raise HTTPException(status_code=403, detail="Only admins can create API keys.")
    key, prefix, digest = generate_api_key()
    row = ApiKey(
        org_id=p.org_id, name="getting-started", prefix=prefix, key_hash=digest, scopes=["ingest"], created_by=p.id
    )
    db.add(row)
    await db.commit()
    await audit.append(
        db, p.org_id, p.actor, "api_key.created", row.id, {"name": row.name, "scopes": ["ingest"], "prefix": prefix}
    )
    return await _welcome(request, p, db, new_key=key)


@router.post("/welcome/sample")
async def welcome_sample(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    from agentguard.server.demo import seed_org

    if not p.can("policies:write"):
        raise HTTPException(status_code=403, detail="Only admins can load sample data.")
    org = await db.get(Organization, p.org_id)
    if org is not None:
        await seed_org(db, org, request.app.state.settings)
        await audit.append(db, p.org_id, p.actor, "org.sample_data_loaded", org.id, {})
    return RedirectResponse("/events", status_code=303)
