"""Shared strings (owner: core-platform). Keys: "common.*" and "error.*".

Placeholders use `str.format` syntax. `t()` always supplies `app_title`, `chair_label`
and `currency` from the settings, so any string may use them.
"""

STRINGS: dict[str, str] = {
    "common.trust_notice": (
        "{app_title} is a trust-based departmental coffee ledger. It does not prove anyone's real-world identity."
    ),
    "common.privacy": "Privacy",
    "common.home": "Home",
    "common.back_home": "Back to the start page",
    "common.try_again": "Try again",
    "common.skip_to_content": "Skip to content",
    # Error pages (status code or service error code). Never include technical details.
    "error.title": "Something went wrong",
    "error.bad_request": "The request could not be processed. Please go back and try again.",
    "error.forbidden": "You are not allowed to do this.",
    "error.csrf": "This form has expired or was sent from another site. Please reload the page and try again.",
    "error.not_found": "This page does not exist.",
    "error.method_not_allowed": "This action is not available here.",
    "error.too_large": "The request is too large.",
    "error.rate_limited": "Too many attempts. Please wait a few minutes and try again.",
    "error.transient": "The server is busy right now. Please try again in a moment.",
    "error.internal": "An unexpected error occurred. Please try again later.",
    "error.user_inactive": "This profile is no longer active. Please ask an administrator.",
    "error.no_price": "No coffee price has been configured yet, so nothing was recorded. Please tell an administrator.",
    "error.already_reversed": "This entry has already been reversed.",
    "error.undo_not_allowed": "This entry can no longer be undone.",
    "error.invalid_input": "Some of the entered data is not valid. Please check it and try again.",
    "error.invalid_amount": "The amount is not valid. Use a format like 12.50 or 12,50.",
    "error.conflict": "This action conflicts with a change made in the meantime. Please reload and try again.",
    "error.error": "The request could not be processed.",
}
