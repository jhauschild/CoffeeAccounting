"""Mail texts (PLAN-v2 section 1). Each function returns `(subject, body)`; all wording lives in
`strings_mail` (keys `mail.*`). Plain text only.

Subjects are static (no user-controlled text). User-controlled names appear only inside bodies, reduced to a
single clean line. Links are built from `PUBLIC_BASE_URL`; the token is percent-encoded.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from app.config import get_settings
from app.services.mail import clean_header_text
from app.strings import t

MAX_NAME_IN_BODY = 100


def _base() -> str:
    return get_settings().public_base_url.rstrip("/")


def _link(path: str, token: str) -> str:
    return f"{_base()}/{path}/{quote(token, safe='')}"


_URL_RE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:)?//\S*|\bwww\.\S*", re.IGNORECASE)


def neutralise_urls(text: str) -> str:
    """Remove URL-looking text (anything with `://`, `//host` or `www.`) and collapse whitespace. Display names
    are free text; a link in one must never read as part of the mail."""
    text = _URL_RE.sub(" ", text or "")
    return " ".join(text.replace("://", " ").split())


def _name(text: str) -> str:
    return neutralise_urls(clean_header_text(text, MAX_NAME_IN_BODY))


def duration_text(*, minutes: int | None = None, hours: int | None = None, days: int | None = None) -> str:
    """"1 hour", "24 hours", "7 days", "90 minutes": whole units where they divide evenly."""
    if days is not None:
        return t("mail.duration.day") if days == 1 else t("mail.duration.days", n=days)
    if hours is not None:
        minutes = hours * 60
    minutes = int(minutes or 0)
    if minutes and minutes % 60 == 0:
        h = minutes // 60
        return t("mail.duration.hour") if h == 1 else t("mail.duration.hours", n=h)
    return t("mail.duration.minute") if minutes == 1 else t("mail.duration.minutes", n=minutes)


def _signature() -> str:
    return t("mail.signature")


def member_verification(token: str) -> tuple[str, str]:
    s = get_settings()
    body = t("mail.verify.body", link=_link("verify", token), validity=duration_text(hours=s.verification_ttl_hours),
             ignore=t("mail.ignore_if_unexpected"), signature=_signature())
    return t("mail.verify.subject"), body


def already_registered() -> tuple[str, str]:
    """No link and no token: the visitor is pointed to sign-in and "Forgot password"."""
    body = t("mail.exists.body", signin_url=f"{_base()}/login", signature=_signature())
    return t("mail.exists.subject"), body


def guest_sponsor_request(*, guest_display_name: str, guest_username: str, token: str) -> tuple[str, str]:
    s = get_settings()
    body = t("mail.sponsor.body", guest_name=_name(guest_display_name), guest_username=_name(guest_username),
             link=_link("verify", token), validity=duration_text(days=s.guest_approval_ttl_days),
             ignore=t("mail.ignore_if_unexpected"), signature=_signature())
    return t("mail.sponsor.subject"), body


def password_reset(*, username: str, token: str, for_guest: bool = False) -> tuple[str, str]:
    """Names the account. `for_guest`: the mail goes to the sponsor, so it says so."""
    s = get_settings()
    body = t("mail.reset.body", username=_name(username), link=_link("reset", token),
             validity=duration_text(minutes=s.reset_ttl_minutes), signature=_signature())
    if for_guest:
        body += "\n" + t("mail.reset.guest_note", username=_name(username))
    return t("mail.reset.subject"), body


def guest_approved(*, guest_username: str) -> tuple[str, str]:
    body = t("mail.guest_approved.body", guest_username=_name(guest_username), signin_url=f"{_base()}/login",
             signature=_signature())
    return t("mail.guest_approved.subject"), body


def guest_rejected(*, guest_username: str) -> tuple[str, str]:
    body = t("mail.guest_rejected.body", guest_username=_name(guest_username), signature=_signature())
    return t("mail.guest_rejected.subject"), body


def account_deactivated(*, username: str, restore_until, reason: str = "admin") -> tuple[str, str]:
    """Notice that an account was anonymized; includes the restore deadline and sign-in URL."""
    from app.timeutil import format_local

    inactive_note = t("mail.deactivate.inactive_extra") if reason == "inactive" else ""
    body = t(
        "mail.deactivate.body",
        inactive_note=inactive_note,
        username=_name(username),
        restore_until=format_local(restore_until) if hasattr(restore_until, "isoformat") else str(restore_until),
        signin_url=f"{_base()}/login",
        signature=_signature(),
    )
    return t("mail.deactivate.subject"), body


def deactivate_please_pay(*, username: str, amount: str, contacts: str) -> tuple[str, str]:
    body = t(
        "mail.deactivate_please_pay.body",
        username=_name(username),
        amount=amount,
        contacts=contacts,
        signature=_signature(),
    )
    return t("mail.deactivate_please_pay.subject"), body


def deactivate_has_credit(*, username: str, amount: str, contacts: str) -> tuple[str, str]:
    body = t(
        "mail.deactivate_has_credit.body",
        username=_name(username),
        amount=amount,
        contacts=contacts,
        signature=_signature(),
    )
    return t("mail.deactivate_has_credit.subject"), body


def deactivate_collect_owed(
    *, display_name: str, username: str, chair_name: str, amount: str, admin_url: str
) -> tuple[str, str]:
    body = t(
        "mail.deactivate_collect_owed.body",
        display_name=_name(display_name),
        username=_name(username),
        chair_name=_name(chair_name),
        amount=amount,
        admin_url=admin_url,
        signature=_signature(),
    )
    return t("mail.deactivate_collect_owed.subject"), body


def deactivate_no_group_admin(
    *, display_name: str, username: str, chair_name: str, amount: str, balance_kind: str, admin_url: str
) -> tuple[str, str]:
    body = t(
        "mail.deactivate_no_group_admin.body",
        display_name=_name(display_name),
        username=_name(username),
        chair_name=_name(chair_name),
        amount=amount,
        balance_kind=balance_kind,
        admin_url=admin_url,
        signature=_signature(),
    )
    return t("mail.deactivate_no_group_admin.subject"), body
