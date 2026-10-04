# Task 4.3: group-admin role button, /admin/admins, sponsor reassignment UI

Status: done. Commit "admin: group-admin roles, admins page, sponsor reassignment (task 4.3)".

## What changed
- New `app/services/roles.py` (services never commit):
  - `promote_group_admin(db, *, head_admin, user_id, ip=None, now=None) -> AdminUser`: head admin only (`authz.require_global`), never oneself (`Forbidden`, reason `self`). Needs an ACTIVE VERIFIED MEMBER: `registration.ensure_member` (guest/legacy: `Forbidden`, reason `not_member`), inactive/unverified/merged: `UserInactive`, unknown: `NotFound`, already active: `Conflict` (reason `already_group_admin`), login name held by a CLI admin: `Conflict` (reason `username_taken`). Creates the `admin_users` row (role `chair`, `user_id` link, `password_hash` NULL, username = account username) or re-activates the existing row of a former group admin (same row, username mirror re-synced). Audit `admin.group_admin_promoted` (actor head admin, target_type `user`, target_id the member, metadata admin_id, chair_id, reactivated).
  - `demote_group_admin(db, *, head_admin, user_id, ip=None, now=None) -> int`: returns the held amount (`groups.held`, cents). Sets `active=False`, revokes ALL admin sessions of the row, KEEPS role `chair` and the user link, never deletes. `NotFound` if not a group admin, `Conflict` (reason `already_removed`) if already removed, `Forbidden` reason `self` for oneself, `Forbidden` reason `last_global_admin` / `InvalidInput` if the linked row is a head admin (a head row is never touched). Audit `admin.group_admin_demoted` (metadata admin_id, sessions_revoked, held_cents).
  - Read models: `role_info(db, user)` (detail page), `list_role_holders(db, head_admin)` (head admins + all group admins, current and former, held), `sponsor_candidates(db, head_admin, q, exclude=)` (active verified members by folded display name), `active_global_count`.
- New `app/web/admin_roles.py` (included in `routes_admin.py`, one-line change as in 4.2/4.4; all routes head admin only, group admins get 403):
  - `GET /admin/admins`
  - `POST /admin/users/{user_id}/group-admin/promote` and `.../demote` (CSRF, no step-up); flash keys `group_admin_added`, `group_admin_removed`, `group_admin_removed_held` (demotion while money is still held), errors `not_member`, `role_self`, `last_global_admin`, `already_group_admin`, `already_removed`, `username_taken`.
  - `GET /admin/users/{user_id}/sponsor?q=` (search page, non-guests are redirected back with `err=not_a_guest`) and `POST /admin/users/{user_id}/sponsor` (`sponsor_id`) calling `registration.reassign_sponsor` (guest's chair becomes the new sponsor's chair, audited `guest.sponsor_reassigned`).
- Templates: `admin/admins.html`, `admin/sponsor.html` (new); `user_detail.html` has a role card for members (ONE button "Make group admin" / "Remove group admin", hidden for guests and for group admins; warning with the held amount and link to `/admin/groups`; former admins labelled) and a sponsor card for guests (head admin only); nav link "Admins" (head admin only) in `base.html`. Strings in `strings_admin.py` (`admin.role.*`, `admin.admins.*`, `admin.sponsor.*`, new msg/err keys).
- `admin_users.user_detail` passes `role` (`roles.role_info`, head admin only; `None` for group admins).

## Decisions
- Role changes are NOT step-up actions: the routes are in `NON_BALANCE_POSTS` of `tests/test_admin_routes_authz.py` (with POST_DATA entries); all new routes are in the route-enumeration tests (anonymous, user cookie, group admin in/out of scope, head admin).
- Audit target is the member (`target_type="user"`) so role changes show up in the person's audit table on the detail page.
- No chair picker and no TOTP reset on promote: a re-promoted admin keeps TOTP state from before. A newly promoted admin must enrol TOTP at first login (existing 4.1 behaviour with `BALANCE_TOTP_REQUIRED`).
- The "last head admin" rule is enforced by construction (role services never deactivate a head row; self is refused). CLI `disable-admin` is unchanged (existing tests disable the only head admin).
- Account password changes still do not revoke a linked admin's sessions (noted in 4.1; not part of this task).

## Tests
- `tests/test_admin_roles.py` (28): promote member, link/no hash/username mirror, scope = own chair, two group admins per chair, guest refused (service and route), inactive/unverified/unknown, double promote, group admin and inactive head cannot promote/demote, username clash, head cannot promote/demote self, head rows protected, demote revokes sessions and keeps role + link, held amount returned and former admin still listed by groups and `/admin/admins`, re-promote reactivates the same row, sign-in works after promotion and fails after demotion, audit actor/target, button visibility (member, guest, group admin), warning on demotion, CSRF, `/admin/admins` content, sponsor search filter, reassign (chair change, audit), guest-as-sponsor refused, group admin 403 for sponsor routes.
- `tests/test_admin_routes_authz.py`: new routes in the module list, POST_DATA and NON_BALANCE_POSTS.

## Known-broken
- None.
