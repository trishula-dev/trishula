#!/usr/bin/env python3
# test/waf-gate/gen-crs-overrides.py (TR-205, issue #291 row 1; committed
# by the lane-d fix pass per the PR review row) — the crs-overrides.yaml
# GENERATOR. Reads the pinned CRS regression corpus (test/waf-gate/
# pins.yaml names the release) and the committed case list
# (crs-subset.txt) and writes the status override map the go-ftw shadow
# leg feeds (--overrides):
#   - a test whose stages expect CRS rule ids (expect_ids non-empty) maps
#     to status 403 — the detection-record block shape for the shadow run;
#   - a test with no-expect stages or no log expectation maps to 200 (the
#     engine forwards; the fixture answers 200).
# The map pins ONLY the shadow record now (the CRS enforcement rides the
# compiled fast-path lane — the gate verdict reads the WH-SQLI-001 probe,
# never this map). Regenerate on a corpus-row PR; never edit by hand.
#
# The README one-shot (run from a clean checkout, the corpus per
# pins.yaml v4.30.0):
#
#   python3 test/waf-gate/gen-crs-overrides.py \
#     <corpus>/tests/regression/tests test/waf-gate/crs-overrides.yaml
import sys
from pathlib import Path

import yaml


def classify(test):
    """403 when any stage expects CRS rule ids, else 200."""
    for stage in test.get("stages", []):
        log = (stage.get("output") or {}).get("log") or {}
        if log.get("expect_ids"):
            return 403
    return 200


REASON = {
    403: "the shadow detection record: the CRS-critical row reads block (403)",
    200: "the shadow detection record: the no-rule row reads pass (200)",
}


def generate(corpus_tests_dir, subset_path, out_path):
    corpus_tests_dir = Path(corpus_tests_dir)
    ids = []
    for line in open(subset_path):
        line = line.strip()
        if line and not line.startswith("#"):
            ids.append(line)

    groups = {}  # (rule_id, status) -> [test_ids]
    for rid in ids:
        matches = sorted(corpus_tests_dir.glob(f"**/{rid}.yaml"))
        if not matches:
            raise SystemExit(f"corpus test file for {rid} not found")
        data = yaml.safe_load(open(matches[0]))
        for test in data.get("tests", []):
            status = classify(test)
            groups.setdefault((data["rule_id"], status), []).append(
                test["test_id"])

    header = (
        "# test/waf-gate/crs-overrides.yaml (TR-205, issue #291 row 1) — the CRS\n"
        "# corpus status expectations for the go-ftw SHADOW leg (record-only).\n"
        "# Generated from the pinned corpus (coreruleset v4.30.0) by\n"
        "# test/waf-gate/gen-crs-overrides.py; the committed file reproduces\n"
        "# from a clean checkout with the README command. Rows: a test whose\n"
        "# stages expect CRS rule ids maps to status 403 (the shadow\n"
        "# detection-record shape); a test with no-expect stages or no log\n"
        "# expectation maps to status 200 (the engine forwards; the fixture\n"
        "# answers 200). Regenerate on a corpus-row PR; never edit by hand.\n"
    )
    lines = ['version: "v0.0.0"', "meta:", '  engine: "trishula-waf-gate"',
             '  platform: "cloud"', "test_overrides:"]
    for (rid, status), tids in sorted(groups.items()):
        ids_str = ",".join(str(t) for t in sorted(tids))
        lines.append(f"  - rule_id: {rid}")
        lines.append(f"    test_ids: [{ids_str}]")
        lines.append(f"    reason: '{REASON[status]}'")
        lines.append("    output:")
        lines.append(f"      status: {status}")

    block = sum(1 for _, s in groups if s == 403)
    block_tests = sum(len(t) for (rid, s), t in groups.items() if s == 403)
    total = sum(len(t) for t in groups.values())
    print(f"overrides: {total} tests across {len(groups)} grouped rows "
          f"({block_tests} block tests in {block} rows; "
          f"{total - block_tests} pass tests in {len(groups) - block} rows)",
          file=sys.stderr)
    with open(out_path, "w") as fh:
        fh.write(header)
        fh.write("---\n")
        fh.write("\n".join(lines))
        fh.write("\n")
    return groups


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: gen-crs-overrides.py <corpus-regression-tests-dir> "
              "<output-file>", file=sys.stderr)
        sys.exit(2)
    generate(sys.argv[1], "test/waf-gate/crs-subset.txt", sys.argv[2])
