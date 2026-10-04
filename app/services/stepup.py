"""Step-up confirmation for balance-changing admin actions (PLAN-v2 section 4, rev 4 A7/A8).

Every action that changes a balance is a two-step flow:

1. An entry form POSTs to a *preview* route. `prepare()` parses the form, runs the action inside a
   write transaction that is ALWAYS rolled back (so the preview reports exactly what the real
   action would book, including the resulting balance, and persists nothing), and returns a
   `Prepared` object: a read-only `ConfirmView` plus an HMAC-signed payload (key
   `derive_key("stepup-payload")`) that binds action kind, canonical parameters, a one-time nonce,
   the admin and the admin session. The payload is valid for 10 minutes.
2. The confirm POST (`/admin/stepup/confirm`, the ONLY route that executes) depends on
   `admin_deps.require_stepup`, which calls `authorise()`: payload and nonce are verified, then the
   admin must either have an open `admin_sessions.stepup_until` window, or present a fresh TOTP /
   recovery code (which opens the window for `STEPUP_WINDOW_SECONDS`, fixed, never extended by
   later actions). With `BALANCE_TOTP_REQUIRED=false` (dev) the code prompt is skipped; the
   confirm page, signed payload and nonce remain. `authorise()` returns a `StepupGrant`, the only
   object `run()` accepts. `run()` inserts the nonce into `used_nonces` in the SAME transaction as
   the action (unique violation = `AlreadyExecuted`, nothing is booked twice) and audits the
   execution including how it was authorised. Services never commit: the caller owns the
   transaction (`write_session`).

Adding an action (task 4.4: set balance, remittances): write an `Action` with `parse` (raw form
strings -> canonical JSON-safe params, may raise `ServiceError`), `execute` (calls the ledger/groups
service function; returns an `ActionResult`; use `idempotency_key_for(nonce)` where the service
takes an idempotency key) and `back_path`, then `register(Action(...))`. Add a preview route that
calls `prepare()` and renders the confirm page (`admin_deps.confirm_page`). Nothing else is needed:
the confirm route, nonce, signature, window/code logic and audit are shared. Service functions that
change balances must only be called from registered actions (a test scans `app/web/admin_*.py`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import read_session, write_session
from app.models import AdminSession, AdminUser, ConsumptionEvent, UsedNonce, User
from app.money import parse_money
from app.services import admin_auth, audit, keys, ledger, users
from app.services.errors import InvalidAmount, InvalidInput, NotFound, ServiceError
from app.timeutil import ensure_utc, utcnow

PAYLOAD_TTL_SECONDS = 600
PAYLOAD_SKEW_SECONDS = 60
MAX_PAYLOAD_LENGTH = 4096
KEY_LABEL = "stepup-payload"
NONCE_BYTES = 16
_FIELDS = {"v", "k", "p", "n", "a", "s", "iat"}
_INT_RE = re.compile(r"^[+-]?[0-9]{1,4}$")


# ----- errors -------------------------------------------------------------------------------------
class StepupError(Exception):
    """Base class of the step-up flow's own (non-ServiceError) outcomes."""


class PayloadInvalid(StepupError):
    """Unsigned, tampered, expired, or bound to another admin/session/nonce. `reason` is a short label."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class AlreadyExecuted(StepupError):
    """The nonce was consumed before: the action has already been carried out; nothing is booked again."""

    def __init__(self, kind: str, back_path: str):
        super().__init__(kind)
        self.kind = kind
        self.back_path = back_path


class CodeRequired(StepupError):
    """No open window and no valid code. `error` is None (first prompt), `code_required`,
    `invalid_code` or `rate_limited`; `payload` is the validated payload to show the page again."""

    def __init__(self, payload: "Payload", error: str | None):
        super().__init__(error or "code_required")
        self.payload = payload
        self.error = error


class SessionGone(StepupError):
    """The admin session was revoked while the confirmation was in flight."""


# ----- registry -----------------------------------------------------------------------------------
@dataclass
class ActionResult:
    """What an action did (or, in a preview, would do)."""

    user_id: uuid.UUID                  # the person shown on the confirm page
    balance_user_id: uuid.UUID          # whose resulting balance is shown (merge: the surviving profile)
    amount_cents: int                   # the amount shown (payment: received; adjustment: consumed; ...)
    flash: str                          # `admin.msg.<flash>` shown after the redirect
    path: str                           # where to go after success
    quantity: int | None = None
    note: str | None = None
    extra: dict[str, str] = field(default_factory=dict)   # label key -> already-plain value (names)
    meta: dict = field(default_factory=dict)              # extra audit metadata (ids, no secrets)


@dataclass(frozen=True)
class Action:
    kind: str
    label: str                                                   # string key `admin.stepup.action.<kind>`
    parse: Callable[[Session, AdminUser, dict], dict]           # raw form -> canonical params
    execute: Callable[..., ActionResult]                        # (db, admin, params, *, nonce, ip, now)
    balance_user_id: Callable[[dict], uuid.UUID]                # params -> user whose balance is shown
    back_path: Callable[[dict], str]                            # entry page, for errors / cancel


REGISTRY: dict[str, Action] = {}


def register(action: Action) -> Action:
    if action.kind in REGISTRY:
        raise ValueError(f"step-up action {action.kind!r} already registered")
    REGISTRY[action.kind] = action
    return action


def idempotency_key_for(nonce: str) -> str:
    """Idempotency key for services that take one (payments): derived from the one-time nonce."""
    return f"stepup:{nonce}"


# ----- signed payload -----------------------------------------------------------------------------
def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sig(body: str) -> str:
    return _b64e(hmac.new(keys.derive_key(KEY_LABEL), body.encode("ascii"), hashlib.sha256).digest())


@dataclass(frozen=True)
class Payload:
    kind: str
    params: dict
    nonce: str
    admin_id: str
    session_id: str
    issued_at: int


def sign_payload(*, kind: str, params: dict, nonce: str, admin_id, session_id, now: datetime | None = None) -> str:
    body = {"v": 1, "k": kind, "p": params, "n": nonce, "a": str(admin_id), "s": str(session_id),
            "iat": int((now or utcnow()).timestamp())}
    raw = _b64e(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{raw}.{_sig(raw)}"


def verify_payload(token: str | None, *, now: datetime | None = None) -> Payload:
    """Verified payload; raises `PayloadInvalid` for anything but a fresh, correctly signed payload."""
    if not token or not isinstance(token, str) or len(token) > MAX_PAYLOAD_LENGTH or token.count(".") != 1:
        raise PayloadInvalid("malformed")
    raw, sig = token.split(".")
    try:
        sig_ok = hmac.compare_digest(sig.encode("ascii"), _sig(raw).encode("ascii"))
    except (UnicodeEncodeError, ValueError):
        raise PayloadInvalid("malformed") from None
    if not sig_ok:
        raise PayloadInvalid("signature")
    try:
        body = json.loads(_b64d(raw))
    except (ValueError, UnicodeDecodeError):
        raise PayloadInvalid("malformed") from None
    if not isinstance(body, dict) or set(body) != _FIELDS or body["v"] != 1:
        raise PayloadInvalid("fields")
    iat = body["iat"]
    if (not isinstance(iat, int) or isinstance(iat, bool) or not isinstance(body["k"], str)
            or not isinstance(body["p"], dict) or not all(isinstance(body[x], str) for x in ("n", "a", "s"))):
        raise PayloadInvalid("fields")
    age = int((now or utcnow()).timestamp()) - iat
    if age > PAYLOAD_TTL_SECONDS or age < -PAYLOAD_SKEW_SECONDS:
        raise PayloadInvalid("expired")
    return Payload(body["k"], body["p"], body["n"], body["a"], body["s"], iat)


# ----- preview (read-only) ------------------------------------------------------------------------
@dataclass(frozen=True)
class ConfirmView:
    """Everything the confirm page shows (plain values, safe to render after the transaction ended)."""

    kind: str
    label: str
    person: str
    chair: str
    amount_cents: int
    quantity: int | None
    note: str | None
    balance_before_cents: int
    balance_after_cents: int
    extra: dict[str, str]
    back_path: str


@dataclass(frozen=True)
class Prepared:
    view: ConfirmView
    token: str
    nonce: str


class _DryRunDone(Exception):
    """Raised to roll the preview transaction back."""


def _view(admin: AdminUser, action: Action, params: dict, nonce: str, ip: str | None, raw: dict | None,
          now: datetime | None) -> tuple[ConfirmView, dict]:
    """Run the action inside a write transaction that is always rolled back; returns (view, params)."""
    out: dict = {}
    try:
        with write_session() as db:
            actor = db.get(AdminUser, admin.id)
            if actor is None:
                raise NotFound("administrator not found")
            if raw is not None:
                params = action.parse(db, actor, raw)
            balance_user = action.balance_user_id(params)
            before = ledger.get_totals(db, balance_user).balance_cents
            result = action.execute(db, actor, params, nonce=nonce, ip=ip, now=now)
            after = ledger.get_totals(db, result.balance_user_id).balance_cents
            person = db.get(User, result.user_id)
            out["view"] = ConfirmView(
                kind=action.kind, label=action.label, person=person.display_name, chair=person.chair.short_name,
                amount_cents=result.amount_cents, quantity=result.quantity, note=result.note,
                balance_before_cents=before, balance_after_cents=after, extra=dict(result.extra),
                back_path=action.back_path(params))
            out["params"] = params
            raise _DryRunDone  # roll back: a preview persists nothing
    except _DryRunDone:
        pass
    return out["view"], out["params"]


def prepare(*, admin: AdminUser, session_id, kind: str, raw: dict, ip: str | None = None,
            now: datetime | None = None) -> Prepared:
    """Preview of `kind` for the raw form values: view + signed payload. Raises `ServiceError` exactly as
    the real action would (invalid amount, out of scope, already reversed, ...). Writes nothing."""
    action = REGISTRY.get(kind)
    if action is None:
        raise NotFound("unknown action")
    nonce = secrets.token_urlsafe(NONCE_BYTES)
    view, params = _view(admin, action, {}, nonce, ip, raw, now)
    token = sign_payload(kind=kind, params=params, nonce=nonce, admin_id=admin.id, session_id=session_id, now=now)
    return Prepared(view, token, nonce)


def view_for(*, admin: AdminUser, payload: Payload, ip: str | None = None, now: datetime | None = None) -> ConfirmView:
    """The confirm view of an already signed payload (to show the page again, e.g. after a wrong code)."""
    action = REGISTRY.get(payload.kind)
    if action is None:
        raise PayloadInvalid("action")
    view, _ = _view(admin, action, payload.params, payload.nonce, ip, None, now)
    return view


# ----- authorisation ------------------------------------------------------------------------------
_MINT = object()


@dataclass(frozen=True)
class StepupGrant:
    """Proof that a payload, its nonce and a step-up authorisation were verified. Only `authorise()` makes one;
    `run()` refuses anything else."""

    admin: AdminUser
    action: Action
    params: dict
    nonce: str
    authorised_by: str   # "window" | "totp" | "recovery_code" | "not_required"
    _mint: object = field(default=None, repr=False)


def _int_ok(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _reject(admin: AdminUser, reason: str, ip: str | None, now: datetime | None) -> None:
    """Audit a rejected payload (never the payload itself) in its own short transaction."""
    with write_session() as db:
        audit.log(db, actor_type="admin", actor_id=admin.id, action="stepup.rejected", target_type="admin",
                  target_id=admin.id, metadata={"reason": reason}, ip=ip, now=now)


def authorise(*, admin: AdminUser, session: AdminSession, token: str | None, nonce: str | None, code: str | None,
              ip: str, now: datetime | None = None) -> StepupGrant:
    """Verify the signed payload and the step-up authorisation of a confirm POST.

    Raises `PayloadInvalid` (nothing written except an audit entry), `AlreadyExecuted`, `CodeRequired`
    (no open window and no valid code; a wrong code is counted by the admin rate limiter and audited),
    or `SessionGone`. Otherwise returns the grant for `run()`.
    """
    now = ensure_utc(now) if now is not None else utcnow()
    try:
        payload = verify_payload(token, now=now)
        if payload.admin_id != str(admin.id) or payload.session_id != str(session.id):
            raise PayloadInvalid("binding")
        if nonce is None or not hmac.compare_digest(nonce.encode("utf-8"), payload.nonce.encode("utf-8")):
            raise PayloadInvalid("nonce")
        action = REGISTRY.get(payload.kind)
        if action is None:
            raise PayloadInvalid("action")
    except PayloadInvalid as exc:
        _reject(admin, exc.reason, ip, now)
        raise
    with read_session() as db:
        spent = db.scalar(select(UsedNonce.id).where(UsedNonce.nonce == payload.nonce)) is not None
    if spent:
        raise AlreadyExecuted(action.kind, action.back_path(payload.params))
    if not get_settings().balance_totp_required:
        return StepupGrant(admin, action, payload.params, payload.nonce, "not_required", _MINT)
    with read_session() as db:
        fresh = db.get(AdminSession, session.id)
        if fresh is None or fresh.revoked_at is not None or fresh.admin_id != admin.id:
            raise SessionGone()
        window_open = admin_auth.has_open_stepup(fresh, now)
    if window_open:
        return StepupGrant(admin, action, payload.params, payload.nonce, "window", _MINT)
    if not (code or "").strip():
        raise CodeRequired(payload, "code_required")
    with write_session() as db:
        status = admin_auth.open_stepup(db, session_id=session.id, admin=admin, code=code or "", ip=ip, now=now)
    if status in ("totp", "recovery_code", "window"):
        return StepupGrant(admin, action, payload.params, payload.nonce,
                           "window" if status == "window" else status, _MINT)
    if status == "no_session":
        raise SessionGone()
    raise CodeRequired(payload, "rate_limited" if status == "limited" else "invalid_code")


def run(db: Session, grant: StepupGrant, *, ip: str | None = None, now: datetime | None = None) -> ActionResult:
    """Execute the granted action in the caller's write transaction (never commits).

    The nonce is inserted into `used_nonces` first, in this same transaction: a unique violation means
    the action already ran (`AlreadyExecuted`). If the action raises, the caller's rollback also discards
    the nonce, so a failed action can be retried from the same confirm page.
    """
    if not isinstance(grant, StepupGrant) or grant._mint is not _MINT:
        raise PermissionError("a step-up grant from authorise() is required")
    now = ensure_utc(now) if now is not None else utcnow()
    try:
        with db.begin_nested():
            db.add(UsedNonce(nonce=grant.nonce, consumed_at=now))
            db.flush()
    except IntegrityError as exc:
        if not ledger._is_unique_violation(exc):
            raise
        raise AlreadyExecuted(grant.action.kind, grant.action.back_path(grant.params)) from None
    actor = db.get(AdminUser, grant.admin.id)
    if actor is None:
        raise NotFound("administrator not found")
    result = grant.action.execute(db, actor, grant.params, nonce=grant.nonce, ip=ip, now=now)
    audit.log(db, actor_type="admin", actor_id=actor.id, action="stepup.executed", target_type="user",
              target_id=result.user_id,
              metadata={"kind": grant.action.kind, "authorised_by": grant.authorised_by,
                        "amount_cents": result.amount_cents, **result.meta},
              ip=ip, now=now)
    return result


# ----- actions: payment, adjustment, reversal, merge ----------------------------------------------
def _uuid(value, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        raise InvalidInput(f"invalid {what}") from None


def _optional_uuid(value) -> uuid.UUID | None:
    if value is None or str(value).strip() == "":
        return None
    return _uuid(value, "identifier")


def _note(value) -> str | None:
    value = (value or "").strip() if isinstance(value, str) else None
    return value or None


def _detail(user_id) -> str:
    return f"/admin/users/{user_id}"


def _parse_payment(db: Session, admin: AdminUser, raw: dict) -> dict:
    cents = parse_money(raw.get("amount", ""), allow_negative=True, allow_zero=False)
    correction = _optional_uuid(raw.get("correction_of"))
    return {"user_id": str(_uuid(raw.get("user_id"), "user")), "amount_cents": cents, "note": _note(raw.get("note")),
            "correction_of": str(correction) if correction else None}


def _exec_payment(db: Session, admin: AdminUser, params: dict, *, nonce: str, ip, now) -> ActionResult:
    uid = _uuid(params.get("user_id"), "user")
    cents = params.get("amount_cents")
    if not _int_ok(cents):
        raise InvalidAmount("invalid amount")
    correction = _optional_uuid(params.get("correction_of"))
    payment = ledger.add_payment(db, admin=admin, user_id=uid, amount_cents=cents, note=params.get("note"),
                                 correction_of_id=correction, idempotency_key=idempotency_key_for(nonce), ip=ip,
                                 now=now)
    shown = users.effective_user_id(db, uid) or uid
    return ActionResult(user_id=shown, balance_user_id=shown, amount_cents=cents, flash="payment_recorded",
                        path=_detail(uid), note=params.get("note"), meta={"payment_id": str(payment.id)})


def _parse_adjustment(db: Session, admin: AdminUser, raw: dict) -> dict:
    quantity = (raw.get("quantity") or "").strip()
    if not _INT_RE.match(quantity):
        raise InvalidAmount("quantity must be a whole number")
    qty = int(quantity)
    amount = (raw.get("amount") or "").strip()
    if amount:
        cents = parse_money(amount, allow_negative=True, allow_zero=True)
    else:  # empty: quantity x the price in effect now, fixed in the payload so the page shows the real amount
        cents = ledger.adjustment_default_amount(db, qty)
        if cents is None:
            from app.services.errors import NoPriceConfigured
            raise NoPriceConfigured("no price configured; enter the amount explicitly")
    return {"user_id": str(_uuid(raw.get("user_id"), "user")), "quantity": qty, "amount_cents": cents,
            "note": _note(raw.get("note"))}


def _exec_adjustment(db: Session, admin: AdminUser, params: dict, *, nonce: str, ip, now) -> ActionResult:
    uid = _uuid(params.get("user_id"), "user")
    qty, cents = params.get("quantity"), params.get("amount_cents")
    if not _int_ok(qty) or not _int_ok(cents):
        raise InvalidAmount("invalid adjustment")
    event = ledger.add_adjustment(db, admin=admin, user_id=uid, quantity=qty, amount_cents=cents,
                                  note=params.get("note"), ip=ip, now=now)
    shown = users.effective_user_id(db, uid) or uid
    return ActionResult(user_id=shown, balance_user_id=shown, amount_cents=cents, quantity=qty,
                        flash="adjustment_recorded", path=_detail(uid), note=params.get("note"),
                        meta={"event_id": str(event.id)})


def _parse_reversal(db: Session, admin: AdminUser, raw: dict) -> dict:
    return {"user_id": str(_uuid(raw.get("user_id"), "user")), "event_id": str(_uuid(raw.get("event_id"), "event")),
            "note": _note(raw.get("note"))}


def _exec_reversal(db: Session, admin: AdminUser, params: dict, *, nonce: str, ip, now) -> ActionResult:
    uid, eid = _uuid(params.get("user_id"), "user"), _uuid(params.get("event_id"), "event")
    event = db.get(ConsumptionEvent, eid)
    if event is None or users.effective_user_id(db, event.user_id) != (users.effective_user_id(db, uid) or uid):
        raise NotFound("event not found")  # the event must belong to the profile in the URL
    reversal = ledger.admin_reverse_event(db, admin=admin, event_id=eid, note=params.get("note"), ip=ip, now=now)
    shown = users.effective_user_id(db, uid) or uid
    return ActionResult(user_id=shown, balance_user_id=shown, amount_cents=reversal.amount_cents,
                        quantity=reversal.quantity, flash="event_reversed", path=_detail(uid),
                        note=params.get("note"), meta={"reversal_id": str(reversal.id), "event_id": str(eid)})


def _parse_merge(db: Session, admin: AdminUser, raw: dict) -> dict:
    return {"user_id": str(_uuid(raw.get("user_id"), "user")), "target_id": str(_uuid(raw.get("target_id"), "target"))}


def _exec_merge(db: Session, admin: AdminUser, params: dict, *, nonce: str, ip, now) -> ActionResult:
    dup_id, target_id = _uuid(params.get("user_id"), "user"), _uuid(params.get("target_id"), "target")
    moved = ledger.get_totals(db, dup_id).balance_cents
    target = users.merge_users(db, admin=admin, duplicate_id=dup_id, target_id=target_id, ip=ip, now=now)
    return ActionResult(user_id=dup_id, balance_user_id=target.id, amount_cents=moved, flash="merged",
                        path=_detail(target.id),
                        extra={"into": f"{target.display_name} ({target.chair.short_name})"},
                        meta={"merged_into_id": str(target.id)})


register(Action("payment", "admin.stepup.action.payment", _parse_payment, _exec_payment,
                lambda p: _uuid(p.get("user_id"), "user"), lambda p: _detail(p.get("user_id"))))
register(Action("adjustment", "admin.stepup.action.adjustment", _parse_adjustment, _exec_adjustment,
                lambda p: _uuid(p.get("user_id"), "user"), lambda p: _detail(p.get("user_id"))))
register(Action("reversal", "admin.stepup.action.reversal", _parse_reversal, _exec_reversal,
                lambda p: _uuid(p.get("user_id"), "user"), lambda p: _detail(p.get("user_id"))))
register(Action("merge", "admin.stepup.action.merge", _parse_merge, _exec_merge,
                lambda p: _uuid(p.get("target_id"), "target"), lambda p: f"/admin/users/{p.get('user_id')}/merge"))


# Names of the services that change balances: only registered actions (this module) may call them.
BALANCE_SERVICE_CALLS = ("add_payment", "add_adjustment", "admin_reverse_event", "merge_users", "set_balance",
                         "record_remittance")
