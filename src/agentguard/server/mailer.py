"""Outbound account email (verification, password reset) over SMTP."""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
import urllib.parse
from email.message import EmailMessage

from agentguard.server.settings import ServerSettings

log = logging.getLogger(__name__)


def _send_sync(settings: ServerSettings, to: str, subject: str, text: str) -> None:
    if not settings.smtp_url:
        raise RuntimeError("SMTP is not configured (AGENTGUARD_SMTP_URL)")
    u = urllib.parse.urlsplit(settings.smtp_url)
    msg = EmailMessage()
    msg["From"] = settings.mail_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    ctx = ssl.create_default_context()
    host, port = u.hostname or "localhost", u.port
    if u.scheme == "smtps":
        with smtplib.SMTP_SSL(host, port or 465, context=ctx, timeout=15) as s:
            if u.username:
                s.login(urllib.parse.unquote(u.username), urllib.parse.unquote(u.password or ""))
            s.send_message(msg)
        return
    with smtplib.SMTP(host, port or 587, timeout=15) as s:
        if s.has_extn("starttls"):
            s.starttls(context=ctx)
        if u.username:
            s.login(urllib.parse.unquote(u.username), urllib.parse.unquote(u.password or ""))
        s.send_message(msg)


async def send(settings: ServerSettings, to: str, subject: str, text: str) -> bool:
    """Send an email; returns False (and logs) instead of raising so sign-up flows stay responsive."""
    try:
        await asyncio.to_thread(_send_sync, settings, to, subject, text)
        return True
    except (OSError, smtplib.SMTPException, RuntimeError) as exc:
        log.error("could not send email to %s: %s", to.rsplit("@", maxsplit=1)[-1], type(exc).__name__)
        return False
