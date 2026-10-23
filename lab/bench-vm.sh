#!/bin/bash
# bench-vm.sh — the bench rig for the dev VM (trishula-build-dev class).
# Run it INSIDE the VM copy of the tree, then read the four sections:
#   G  full suite, new CI shape (p 1 + no_regex_multiline)
#   H  old CI shape control (parallel packages, GOMAXPROCS 4)
#   I  bench verdict walls, new shape (verbose rows)
#   J  prefilter-off control walls (same shape, directive removed)
# The VM stays the A/B surface. Hosted CI stays the calibration surface.
set -uo pipefail
export PATH=/usr/local/go/bin:$PATH
export GOTOOLCHAIN=auto

CONF=test/crs-differential/testdata/seclang/engine.conf

echo "== G: full suite, new CI shape (p 1 + no_regex_multiline)"
go test -tags coraza.rule.no_regex_multiline -p 1 ./... -count=1 2>&1 \
  | grep -E '^(ok|FAIL|---)'

echo "== H: old CI shape control (parallel, GOMAXPROCS=4)"
GOMAXPROCS=4 go test ./... -count=1 2>&1 | grep -E '^(ok|FAIL|---)'

echo "== I: bench verdict walls, new CI shape"
go test -tags coraza.rule.no_regex_multiline -run TestBudgetVerdictsOnLivePath \
  ./test/bench -count=1 -v 2>&1 \
  | grep -E 'MEASURED|M2 CELL|P50-BOUND|unmet rows|^--- (FAIL|PASS)|^(ok|FAIL)'

echo "== J: prefilter-off control (same shape, directive removed)"
cp "$CONF" "$CONF.bench-vm-bak"
trap 'mv "$CONF.bench-vm-bak" "$CONF"' EXIT
sed -i '/^SecRxPreFilter On$/d' "$CONF"
go test -tags coraza.rule.no_regex_multiline -run TestBudgetVerdictsOnLivePath \
  ./test/bench -count=1 -v 2>&1 \
  | grep -E 'MEASURED|M2 CELL|unmet rows|^--- (FAIL|PASS)|^(ok|FAIL)'

echo "== done"
