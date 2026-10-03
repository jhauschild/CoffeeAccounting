# Keeping the code safe between sessions

Session containers are temporary. The repo travels as a git bundle in the user's CoffeeProject folder.
Start of a session: stage `coffee-ledger.bundle` from the folder, `git clone` it, `git checkout v2`.
End of a session or gate: `git bundle create coffee-ledger-v2.bundle --all`, then write it back to the folder with the commit tool (use the mtime guard). Never overwrite `coffee-ledger.bundle` (the v1 original) or the checkpoints.
