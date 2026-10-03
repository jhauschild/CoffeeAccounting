"""User-facing strings for the user web flow (owner: user-web agent). Keys: "user.*"."""

STRINGS: dict[str, str] = {
    # Home
    "user.home.title": "Welcome",
    "user.home.hello": "Hello, {name}",
    "user.home.intro": (
        "Scan the QR code on the coffee machine to record a coffee. You can also record one with the buttons below."
    ),
    "user.home.single": "Record a single",
    "user.home.double": "Record a double",
    "user.home.account": "My account",
    "user.home.guest_intro": (
        "{app_title} records coffee consumption in the department. To record a coffee, scan the QR code on the "
        "coffee machine. The first time you need the department access code and a profile."
    ),
    "user.home.get_started": "Get started",
    "user.home.left": "This browser has been removed. Scan the QR code again to continue.",
    # Scan
    "user.scan.title_single": "Record a single",
    "user.scan.title_double": "Record a double",
    "user.scan.recording": "Recording your coffee...",
    "user.scan.button_single": "Record single",
    "user.scan.button_double": "Record double",
    "user.scan.hint": "If nothing happens, tap the button.",
    "user.scan.expired_title": "This scan has expired",
    "user.scan.expired_body": "The page was open for too long or the link is not valid. Nothing was recorded. Please scan the QR code again.",
    "user.scan.used_title": "This scan was already used",
    "user.scan.used_body": "This request belongs to another coffee that has already been recorded. Please scan the QR code again.",
    "user.scan.rescan": "Scan again",
    "user.scan.no_price_title": "Price not configured yet",
    "user.scan.no_price_body": "No coffee price has been configured yet, so nothing was recorded. Please tell an administrator.",
    "user.scan.inactive_title": "Profile not active",
    "user.scan.inactive_body": "Your profile is no longer active, so nothing was recorded. Please ask an administrator.",
    # Pending coffee notices
    "user.pending.single": "Your single coffee will be recorded as soon as you have chosen or created your profile.",
    "user.pending.double": "Your double coffee will be recorded as soon as you have chosen or created your profile.",
    "user.pending.expired": (
        "Your earlier scan has expired or was already used, so no coffee will be recorded now. "
        "Scan the QR code again after you have finished here."
    ),
    # Join / access gate
    "user.join.title": "Access code",
    "user.join.intro": "Please enter the department access code. You will find it on the sign next to the coffee machine.",
    "user.join.code": "Access code",
    "user.join.submit": "Continue",
    "user.join.wrong": "That access code is not correct.",
    "user.join.choose_title": "Who are you?",
    "user.join.choose_new": "Create a new profile",
    "user.join.choose_new_hint": "First time here? Create a profile with your name and {chair_label}.",
    "user.join.choose_existing": "Use an existing profile",
    "user.join.choose_existing_hint": "Already have a profile (for example from another browser or phone)? Pick it from the list.",
    # Registration
    "user.register.title": "Create a profile",
    "user.register.name": "Your name",
    "user.register.name_hint": "As colleagues know you. It is shown next to your {chair_label} in profile lists.",
    "user.register.chair": "{chair_label}",
    "user.register.chair_choose": "Choose...",
    "user.register.privacy": "I have read the privacy information and understand that this is a trust-based ledger.",
    "user.register.privacy_link": "Privacy information",
    "user.register.submit": "Create profile",
    "user.register.existing": "Use an existing profile instead",
    "user.register.error_ack": "Please confirm the privacy information.",
    "user.register.error_chair": "Please choose a {chair_label}.",
    "user.register.error_name": "Please enter a name (at most {max} characters, no control characters).",
    "user.register.error_token": "The form has expired. Please check your entries and submit again.",
    "user.register.duplicate_title": "This profile may already exist",
    "user.register.duplicate_body": "A profile with this name already exists in this {chair_label}. Is it you?",
    "user.register.duplicate_use": "Use existing profile",
    "user.register.duplicate_continue": "No, create a new profile",
    # Profile selection
    "user.profiles.title": "Choose your profile",
    "user.profiles.trust": (
        "This is a trust-based system. If you choose someone else's profile, your coffee is booked to that person."
    ),
    "user.profiles.search": "Search by name",
    "user.profiles.search_button": "Search",
    "user.profiles.select": "This is me",
    "user.profiles.none": "No matching profile found.",
    "user.profiles.more": "Only the first {n} matches are shown. Please refine your search.",
    "user.profiles.register": "I am not in the list: create a new profile",
    # Done
    "user.done.title": "Coffee recorded",
    "user.done.single": "Single recorded",
    "user.done.double": "Double recorded",
    "user.done.reversed": "This coffee was undone",
    "user.done.shots": "Shots added",
    "user.done.price": "Price per shot",
    "user.done.amount": "Amount charged",
    "user.done.time": "Time",
    "user.done.undo": "Undo this coffee",
    "user.done.undo_hint": "You can undo this coffee for a short time after recording it.",
    "user.done.account": "My account and totals",
    # Totals
    "user.totals.title": "Your totals",
    "user.totals.shots": "Shots consumed",
    "user.totals.consumed": "Amount consumed",
    "user.totals.paid": "Amount paid",
    "user.totals.balance": "Balance (to pay)",
    "user.totals.credit": "Credit {amount}",
    # Account
    "user.account.title": "My account",
    "user.account.profile": "Profile",
    "user.account.price": "Current price per shot",
    "user.account.no_price": "not configured yet",
    "user.account.edit": "Edit profile",
    "user.account.history": "Recent coffees",
    "user.account.history_empty": "No coffees recorded yet.",
    "user.account.payments": "Recent payments",
    "user.account.payments_empty": "No payments recorded yet.",
    "user.account.col_time": "Time",
    "user.account.col_type": "Type",
    "user.account.col_shots": "Shots",
    "user.account.col_amount": "Amount",
    "user.account.type_single": "Single",
    "user.account.type_double": "Double",
    "user.account.type_reversal": "Undo",
    "user.account.type_adjustment": "Adjustment",
    "user.account.reversed": "(undone)",
    "user.account.payment": "Payment",
    "user.account.leave": "Remove this browser",
    "user.account.leave_hint": "Signs this browser out. Your profile and ledger are kept. You can choose your profile again later.",
    "user.account.notice_saved": "Your profile has been saved.",
    "user.account.notice_registered": "Your profile is ready. Scan the QR code to record a coffee.",
    "user.account.notice_expired": (
        "Your profile is ready. The earlier scan had expired or was already used, so no coffee was recorded. "
        "Please scan the QR code again."
    ),
    "user.account.notice_no_price": (
        "Your profile is ready, but no coffee price has been configured yet, so nothing was recorded. "
        "Please tell an administrator and scan again later."
    ),
    # Edit
    "user.edit.title": "Edit profile",
    "user.edit.save": "Save",
    "user.edit.cancel": "Cancel",
    "user.edit.chair_note": "Changes of the {chair_label} are logged.",
    # Privacy
    "user.privacy.title": "Privacy",
    "user.privacy.what_title": "What is stored",
    "user.privacy.what": (
        "Your display name and {chair_label}; every coffee and every payment with date, amount and price; "
        "a record of each browser session (a hashed random token, creation, last use and expiry); and an audit "
        "log of administrative actions, including changes of a {chair_label}."
    ),
    "user.privacy.not_stored": "No email address, password, free-text note, analytics, trackers or third-party services are used.",
    "user.privacy.why_title": "Why",
    "user.privacy.why": "To keep a fair account of who owes how much for the shared coffee machine, and to be able to correct mistakes.",
    "user.privacy.who_title": "Who can see it",
    "user.privacy.who": (
        "Administrators of the department can see profiles and ledgers (chair administrators only those of their own "
        "{chair_label}). Anyone with the department access code can see the list of names and chairs, nothing else."
    ),
    "user.privacy.trust": "{app_title} is a trust-based departmental ledger. It does not prove anyone's real-world identity.",
    "user.privacy.retention_title": "Retention",
    "user.privacy.contact_title": "Contact",
    "user.privacy.contact_none": "Please ask the person who runs the coffee machine accounts.",
    "user.privacy.removal": "A profile can only be deactivated by an administrator. Ledger entries are not deleted.",
}
