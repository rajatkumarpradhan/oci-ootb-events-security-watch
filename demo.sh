#!/bin/sh
# Checks the gappy rule set (uncovered event types -> exit 2), then the complete set.
set -u
export PYTHONPATH="$(dirname "$0")/src"

echo "=== Checking samples/gappy-rules.json ==="
python3 -m oci_ootb_events_security_watch samples/gappy-rules.json
echo "exit code: $? (2 = required event types uncovered, expected for the seeded set)"
echo
echo "=== Checking samples/complete-rules.json ==="
python3 -m oci_ootb_events_security_watch samples/complete-rules.json
echo "exit code: $? (0 = full coverage, expected for the complete set)"
