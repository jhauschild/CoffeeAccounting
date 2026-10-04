#!/bin/bash
# Stops what acceptance_up.sh started:  bash docs/status/repro/acceptance_down.sh WORKDIR
W="$1"
for f in dev prod relay; do
  if [ -f "$W/$f.pid" ]; then kill "$(cat "$W/$f.pid")" 2>/dev/null; rm -f "$W/$f.pid"; fi
done
echo "stopped"
