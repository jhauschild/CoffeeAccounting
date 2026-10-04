"""Mail strings (owner: task 2.1). Keys: "mail.*". English, plain text only.

`mail.error.*` are the safe user-facing messages for a `MailError` category (never technical detail).
Placeholders use `str.format` syntax; `mail_templates` fills them (links, validity, names already cleaned).
"""

STRINGS: dict[str, str] = {
    # ----- user-facing messages per MailError category ---------------------------------------------------------
    "mail.error.connect": "The confirmation mail could not be sent right now. Please try again later.",
    "mail.error.tls": "The confirmation mail could not be sent right now. Please try again later.",
    "mail.error.auth": "The confirmation mail could not be sent right now. Please try again later.",
    "mail.error.recipient_rejected": "The mail could not be delivered to this address. Please check it and try again.",
    "mail.error.timeout": "The confirmation mail could not be sent right now. Please try again later.",
    "mail.error.not_configured": "Sending mail is temporarily unavailable. Please try again later.",
    "mail.error.cap_exceeded": "Too many mails were sent recently. Please try again in about an hour.",
    "mail.error.other": "The confirmation mail could not be sent right now. Please try again later.",
    # ----- shared pieces ---------------------------------------------------------------------------------------
    "mail.signature": "-- {app_title}\nThis is an automatic message. Please do not reply to it.",
    "mail.ignore_if_unexpected": "If you did not expect this mail, you can ignore it. Nothing happens unless the link is opened and confirmed.",
    "mail.link_label": "Link:",
    # ----- member verification ---------------------------------------------------------------------------------
    "mail.verify.subject": "{app_title}: confirm your email address",
    "mail.verify.body": (
        "Hello,\n\n"
        "someone registered an account at {app_title} with this email address. To finish, open the link below "
        "and confirm. The link is valid for {validity}.\n\n"
        "{link}\n\n"
        "{ignore}\n\n"
        "{signature}\n"
    ),
    # ----- already registered (no link) ------------------------------------------------------------------------
    "mail.exists.subject": "{app_title}: you already have an account",
    "mail.exists.body": (
        "Hello,\n\n"
        "someone tried to register an account at {app_title} with this email address, but you already have an "
        "account. Please sign in, or use \"Forgot password\" on the sign-in page if you cannot remember your "
        "password.\n\n"
        "{signin_url}\n\n"
        "If this was not you, you can ignore this mail. Nobody can sign in to your account without your "
        "password.\n\n"
        "{signature}\n"
    ),
    # ----- guest sponsor request -------------------------------------------------------------------------------
    "mail.sponsor.subject": "{app_title}: a guest asks you to vouch for them",
    "mail.sponsor.body": (
        "Hello,\n\n"
        "{guest_name} (username: {guest_username}) asked to use {app_title} as a guest and named you as the "
        "person who vouches for them.\n\n"
        "Vouching means: you confirm that this person uses the coffee machine of your institute. If you do "
        "not know them, reject the request.\n\n"
        "You do not need to sign in. Open the link below to see the request and to approve or reject it. "
        "The link is valid for {validity}.\n\n"
        "{link}\n\n"
        "{ignore}\n\n"
        "{signature}\n"
    ),
    # ----- password reset --------------------------------------------------------------------------------------
    "mail.reset.subject": "{app_title}: reset your password",
    "mail.reset.body": (
        "Hello,\n\n"
        "a password reset was requested for the account \"{username}\" at {app_title}. To choose a new "
        "password, open the link below. It can be used once and is valid for {validity}.\n\n"
        "{link}\n\n"
        "If you did not ask for this, you can ignore this mail. Your password stays unchanged until the link "
        "is used.\n\n"
        "{signature}\n"
    ),
    "mail.reset.guest_note": (
        "(This account is a guest account. The reset link goes to the member who vouches for it, so please "
        "pass it on only to the guest \"{username}\" if you know them.)\n"
    ),
    # ----- guest decision (optional receipts; addresses are only known for the sponsor) ------------------------
    "mail.guest_approved.subject": "{app_title}: guest account approved",
    "mail.guest_approved.body": (
        "Hello,\n\n"
        "the guest account \"{guest_username}\" at {app_title} was approved. You can now sign in:\n\n"
        "{signin_url}\n\n"
        "{signature}\n"
    ),
    "mail.guest_rejected.subject": "{app_title}: guest request rejected",
    "mail.guest_rejected.body": (
        "Hello,\n\n"
        "the request for the guest account \"{guest_username}\" at {app_title} was rejected, so no account "
        "was created.\n\n"
        "{signature}\n"
    ),
    # ----- units for validity text -----------------------------------------------------------------------------
    "mail.duration.minute": "1 minute",
    "mail.duration.minutes": "{n} minutes",
    "mail.duration.hour": "1 hour",
    "mail.duration.hours": "{n} hours",
    "mail.duration.day": "1 day",
    "mail.duration.days": "{n} days",
}
