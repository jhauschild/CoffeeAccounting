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
        "coffee machine and sign in with your account."
    ),
    "user.home.sign_in": "Sign in",
    "user.home.create_account": "Create account",
    "user.home.left": "You have been signed out.",
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
    "user.pending.single": "Your single coffee will be recorded as soon as you have signed in.",
    "user.pending.double": "Your double coffee will be recorded as soon as you have signed in.",
    "user.pending.view_site": "You will be taken to the overview as soon as you have signed in.",
    "user.pending.expired": (
        "Your earlier scan has expired or was already used, so no coffee will be recorded now. "
        "Scan the QR code again after you have finished here."
    ),
    # Sign in
    "user.login.title": "Sign in",
    "user.login.intro": "Sign in with your username and password.",
    "user.login.username": "Username",
    "user.login.password": "Password",
    "user.login.submit": "Sign in",
    "user.login.error": "Username or password is not correct.",
    "user.login.forgot": "Forgot your password?",
    "user.login.create": "Create account",
    "user.login.create_hint": "No account yet?",
    "user.login.notice_reset": "Your password has been changed. Please sign in with the new password.",
    "user.limited.title": "Too many attempts",
    "user.limited.body": "Too many attempts. Please wait a few minutes and try again.",
    # Registration (members)
    "user.register.title": "Create account",
    "user.register.intro": (
        "Members of the institute need a verified university e-mail address. Guests need a member of the institute "
        "to vouch for them."
    ),
    "user.register.choose": "Who are you?",
    "user.register.choose_member": "I am a member",
    "user.register.choose_guest": "I am a guest",
    "user.register.member_intro": (
        "Members register with their own university e-mail address (a TUM address). We send a confirmation link to "
        "it; the account exists once you have opened the link."
    ),
    "user.register.guest_intro": (
        "A guest has no university e-mail address. A member of the institute has to vouch for you: enter the "
        "university e-mail address of the member who knows you. We send them a request; you can sign in once they "
        "have approved it."
    ),
    "user.register.guest_title": "Register as a guest",
    "user.register.member_title": "Register as a member",
    "user.register.sponsor_email": "E-mail address of the member who vouches for you",
    "user.register.sponsor_hint": "The university e-mail address of a member of the institute. Your {chair_label} is taken from them.",
    "user.register.guest_submit": "Ask the member to vouch for me",
    "user.register.username": "Username",
    "user.register.username_hint": "3 to 32 characters: lower-case letters, digits, dot, underscore and hyphen. You use it to sign in.",
    "user.register.name": "Your name",
    "user.register.name_hint": "As colleagues know you. It is shown next to your {chair_label}.",
    "user.register.chair": "{chair_label}",
    "user.register.chair_choose": "Choose...",
    "user.register.email": "University e-mail address",
    "user.register.email_hint": "The confirmation link and password reset mails go to this address.",
    "user.register.password": "Password",
    "user.register.password_hint": "At least {min} characters.",
    "user.register.password2": "Repeat the password",
    "user.register.privacy": (
        "I have read the privacy information. I understand that my name, {chair_label}, balance, coffee and payment "
        "history are visible to every verified, signed-in account, and that no e-mail address, username or password "
        "data is ever shown."
    ),
    "user.register.privacy_link": "Privacy information",
    "user.register.submit": "Create account",
    "user.register.have_account": "Already have an account?",
    "user.register.error_name": "Please enter a name (at most {max} characters, no control characters).",
    "user.register.error_chair": "Please choose a {chair_label}.",
    "user.register.error_ack": "Please confirm the privacy information.",
    "user.register.error_form": "Please check your entries and try again.",
    "user.register.error_username_length": "The username must have 3 to 32 characters.",
    "user.register.error_username_chars": "The username may only contain lower-case letters, digits, dot, underscore and hyphen.",
    "user.register.error_username_taken": "This username is already taken. Please choose another one.",
    "user.register.error_email_format": "Please enter a valid e-mail address.",
    "user.register.error_email_domain": "Please use your university e-mail address.",
    "user.register.error_sponsor_format": "Please enter a valid e-mail address.",
    "user.register.error_sponsor_domain": "Please enter the university e-mail address of a member of the institute.",
    "user.register.error_password_too_short": "The password is too short (at least {min} characters).",
    "user.register.error_password_too_long": "The password is too long (at most 128 characters).",
    "user.register.error_password_equals_username": "The password must not be the same as the username.",
    "user.register.error_password_equals_email_local": "The password must not be the same as your e-mail address.",
    "user.register.error_password_mismatch": "The two passwords are not the same.",
    "user.register.sent_title": "Check your mail",
    "user.register.sent_body": (
        "If the address can be used, we have sent a confirmation link to it. The link is valid for a limited time. "
        "Open it on this device to finish creating your account."
    ),
    "user.register.sent_signin": "Back to sign in",
    "user.register.guest_sent_title": "Request sent",
    "user.register.guest_sent_body": (
        "If this address belongs to a registered member, a request was sent to them. Please ask them to check their "
        "inbox and spam folder, and to approve your request. You can sign in after they have approved it."
    ),
    "user.register.guest_sent_check": "Please double-check the address you entered; we cannot tell you whether it was recognised.",
    # Temporarily unavailable (no mail login stored)
    "user.unavailable.title": "Temporarily unavailable",
    "user.unavailable.body": (
        "Registration and password recovery need to send e-mail, and the mail connection is not set up at the "
        "moment. Nothing has been collected. Please ask an administrator and try again later."
    ),
    # E-mail verification
    "user.verify.title": "Confirm your account",
    "user.verify.intro": "Confirm to create this account and sign in.",
    "user.verify.username": "Username",
    "user.verify.name": "Name",
    "user.verify.chair": "{chair_label}",
    "user.verify.submit": "Confirm and sign in",
    "user.verify.taken_title": "This account cannot be created",
    "user.verify.taken_username_body": "The username has been taken in the meantime. Please register again with another username.",
    "user.verify.taken_email_body": "This e-mail address already has an account. Please sign in, or use \"Forgot your password?\".",
    "user.verify.failed_title": "This account cannot be created",
    "user.verify.failed_body": "Something about the registration is no longer valid (for example the chair). Please register again.",
    "user.guest.title": "A guest asks you to vouch for them",
    "user.guest.intro": "Someone has asked you, as a member of the institute, to vouch for them.",
    "user.guest.name": "Name",
    "user.guest.username": "Username",
    "user.guest.chair": "{chair_label}",
    "user.guest.meaning": (
        "If you approve, you confirm that this person uses the coffee machine of your institute. They get a guest "
        "account in your {chair_label}. Password reset mails for the account will be sent to your address. If you do "
        "not know this person, reject the request."
    ),
    "user.guest.approve": "Approve",
    "user.guest.reject": "Reject",
    "user.guest.approved_title": "Guest approved",
    "user.guest.approved_body": "{name} can now sign in with the username {username}.",
    "user.guest.rejected_title": "Request rejected",
    "user.guest.rejected_body": "The request was rejected. No account was created.",
    "user.guest.sponsor_inactive_title": "You can no longer vouch",
    "user.guest.sponsor_inactive_body": "Your own account is no longer an active member account, so this request cannot be approved. Please ask an administrator.",
    "user.guest.taken_title": "This account cannot be created",
    "user.guest.taken_body": "The username has been taken in the meantime. The guest has to register again with another username.",
    "user.guest.failed_title": "This account cannot be created",
    "user.guest.failed_body": "Something about the request is no longer valid (for example the {chair_label}). The guest has to register again.",
    "user.link.invalid_title": "This link is not valid",
    "user.link.invalid_body": "The link is invalid, has expired or was already used. Please request a new one.",
    # Forgot password / reset
    "user.forgot.title": "Forgot your password?",
    "user.forgot.intro": "Enter your username. If the account exists, we send a link to reset the password. For a guest account the mail goes to the sponsor.",
    "user.forgot.username": "Username",
    "user.forgot.submit": "Send reset link",
    "user.forgot.sent_title": "Check your mail",
    "user.forgot.sent_body": "If the account exists, a mail with a reset link has been sent. The link is valid for a limited time.",
    "user.reset.title": "Choose a new password",
    "user.reset.for": "New password for the account {username}.",
    "user.reset.password": "New password",
    "user.reset.submit": "Change password",
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
    "user.done.debt_reminder": (
        "Hey, you're {n} coffees in debt – please settle your balance sometime soon."
    ),
    "user.done.account": "My account and totals",
    "user.done.site": "Overview of the department",
    # Totals
    "user.totals.title": "Your totals",
    "user.totals.shots": "Shots consumed",
    "user.totals.consumed": "Amount consumed",
    "user.totals.paid": "Amount paid",
    "user.totals.month_shots": "Shots this month",
    "user.headline.owes": "Outstanding: {amount}",
    "user.headline.credit": "Credit: {amount}",
    "user.headline.even": "All settled",
    # Account
    "user.account.title": "My account",
    "user.account.profile": "Profile",
    "user.account.name": "Display name",
    "user.account.chair": "{chair_label}",
    "user.account.username": "Username",
    "user.account.email": "E-mail address",
    "user.account.private_hint": "Your username and e-mail address are shown only to you.",
    "user.account.visibility": (
        "Your name, {chair_label}, balance and history are visible to every signed-in account."
    ),
    "user.account.site": "Overview of the department",
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
    "user.account.payment_payment": "Payment",
    "user.account.payment_paid_back": "Paid back to you",
    "user.account.payment_bookkeeping_in": "Balance correction (credited)",
    "user.account.payment_bookkeeping_out": "Balance correction (charged)",
    "user.account.payment_correction": "(correction)",
    "user.account.leave": "Remove this browser",
    "user.account.leave_hint": "Signs this browser out. Your account and ledger are kept; you can sign in again at any time.",
    "user.account.deactivate_title": "Deactivate account",
    "user.account.deactivate_hint": (
        "Your display name on the open site becomes an anonymous Alumni label. Your username and e-mail are "
        "cleared from the account so they can be used by a new registration. Your {chair_label}, password and "
        "ledger history stay. For 90 days you can restore everything by signing in with the same username and "
        "password. After that the original name and e-mail cannot be restored. If you still owe money or have "
        "credit, settlement mails go to you and the group admins. Group admins must ask a head admin to remove "
        "the role first."
    ),
    "user.account.deactivate_confirm": "I understand my name will be anonymized and want to deactivate this account",
    "user.account.deactivate_submit": "Deactivate my account",
    "user.account.error_deactivate_confirm": "Please confirm that you want to deactivate the account.",
    "user.account.error_deactivate_admin": (
        "A group admin cannot deactivate this account. Ask a head admin to remove the group-admin role first."
    ),
    "user.account.notice_password": "Your password has been changed. Your other browsers have been signed out.",
    "user.account.notice_saved": "Your profile has been saved.",
    "user.account.notice_registered": "Your account is ready. Scan the QR code to record a coffee.",
    "user.account.notice_expired": (
        "You are signed in. The earlier scan had expired or was already used, so no coffee was recorded. "
        "Please scan the QR code again."
    ),
    "user.account.notice_no_price": (
        "You are signed in, but no coffee price has been configured yet, so nothing was recorded. "
        "Please tell an administrator and scan again later."
    ),
    # Change password
    "user.password.title": "Change password",
    "user.password.current": "Current password",
    "user.password.new": "New password",
    "user.password.new2": "Repeat the new password",
    "user.password.submit": "Change password",
    "user.password.effect": "All your other browsers are signed out when the password changes. This browser stays signed in.",
    "user.password.error_current": "The current password is not correct.",
    # Edit
    "user.edit.title": "Edit profile",
    "user.edit.save": "Save",
    "user.edit.cancel": "Cancel",
    "user.edit.chair_locked": "As a group admin you cannot change your {chair_label}. Ask a head administrator.",
    "user.edit.chair_fixed": "As a group admin your {chair_label} is fixed. A head administrator can change it.",
    "user.edit.chair_note": "Changes of the {chair_label} are logged.",
    # Privacy
    "user.privacy.title": "Privacy",
    "user.privacy.what_title": "What is stored",
    "user.privacy.what": (
        "Your username, display name and {chair_label}; for members the university e-mail address, for guests the "
        "account of the sponsor who vouched for them; your password only as a salted hash; every coffee and every "
        "payment with date, amount and price; a record of each browser session (a hashed random token, creation, "
        "last use and expiry); and an audit log of administrative actions, including changes of a {chair_label}."
    ),
    "user.privacy.not_stored": "No analytics, trackers or third-party services are used. E-mail addresses are used only to send you the mails described here.",
    "user.privacy.why_title": "Why",
    "user.privacy.why": "To keep a fair account of who owes how much for the shared coffee machine, and to be able to correct mistakes.",
    "user.privacy.who_title": "Who can see it",
    "user.privacy.who": (
        "Every verified, signed-in account can see on the department website: your display name, your {chair_label}, "
        "your balance (in words: what you owe or your credit), the number of coffees (this month and in total), "
        "your complete history of coffees and payments (date, shots, price, amount), the names of the group admins "
        "of each {chair_label} and the group balances (money collected, handed over and still held). Visitors who "
        "are not signed in cannot see any of it."
    ),
    "user.privacy.never_title": "What is never shown",
    "user.privacy.never": (
        "No e-mail address, no username and no password data is ever shown to other users. The same holds for "
        "sessions, IP addresses, notes and the audit log, and for which administrator recorded an entry. Your "
        "username and e-mail address are used only for signing in and for the mails described here."
    ),
    "user.privacy.admins": (
        "Administrators of the department can additionally see accounts and ledgers in the admin area (group admins "
        "only those of their own {chair_label})."
    ),
    "user.privacy.trust": "{app_title} is a trust-based departmental ledger. It does not prove anyone's real-world identity.",
    "user.privacy.retention_title": "Retention",
    "user.privacy.contact_title": "Contact",
    "user.privacy.contact_none": "Please ask the person who runs the coffee machine accounts.",
    "user.privacy.removal": (
        "You can deactivate your account under My account, or an administrator can do it. Deactivation "
        "anonymizes the display name (Alumni N) and clears the login name and e-mail from the account; the "
        "ledger UUID, {chair_label} and history stay. For 90 days you can restore the original identity by "
        "signing in with the same username and password (or an administrator can restore it). After that the "
        "original name and e-mail cannot be restored. Ledger entries and the audit log are never deleted."
    ),
}
