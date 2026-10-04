"""Typed service-layer exceptions. Routes map them to safe pages/messages via `code`."""


class ServiceError(Exception):
    code = "error"

    def __init__(self, message: str = "", **context):
        super().__init__(message or self.code)
        self.context = context


class NotFound(ServiceError):
    code = "not_found"


class Forbidden(ServiceError):
    code = "forbidden"


class UserInactive(ServiceError):
    code = "user_inactive"


class NoPriceConfigured(ServiceError):
    code = "no_price"


class AlreadyReversed(ServiceError):
    code = "already_reversed"


class UndoNotAllowed(ServiceError):
    code = "undo_not_allowed"


class InvalidInput(ServiceError):
    """Generic validation failure (bad name, unknown chair, bad date, ...)."""

    code = "invalid_input"


class InvalidAmount(InvalidInput):
    code = "invalid_amount"


class PaybackExceedsCredit(InvalidAmount):
    """A group admin tried to pay back more than the person's current credit (head admins may)."""

    code = "payback_exceeds_credit"


class InvalidPassword(InvalidInput):
    """Password policy violation. `context["reason"]` is one of too_short, too_long, equals_username,
    equals_email_local; the message never contains the password."""

    code = "invalid_password"


class Conflict(ServiceError):
    code = "conflict"


class RateLimited(ServiceError):
    code = "rate_limited"


class InvalidToken(ServiceError):
    """A mailed one-time token (verification, approval, reset) is unknown, expired or already used.
    One error for all three so the response never says which."""

    code = "invalid_token"


class InvalidCredentials(ServiceError):
    """Sign-in failed. One error for an unknown username, a wrong password and an account that cannot sign in
    (inactive, merged, unverified), so the response never says which."""

    code = "invalid_credentials"
