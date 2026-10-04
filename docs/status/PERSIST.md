# Keeping the code safe between sessions

Session containers are temporary. The repo lives at https://github.com/Sydeva/CoffeeAccounting (private). Branch `v2` is the working branch; `main` is v1.
Start of a session: `git clone https://github.com/Sydeva/CoffeeAccounting.git && git checkout v2`, using a token supplied by the user for that session.
Never write the token into a file, a remote URL or the git config. Pass it per command, for example `git -c http.extraheader="Authorization: Basic $(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)" push`.
Task agents commit locally only; the orchestrator pushes at the end of each session and at every gate.
Fallback: `git bundle create` and write the bundle to the user's CoffeeProject folder.
