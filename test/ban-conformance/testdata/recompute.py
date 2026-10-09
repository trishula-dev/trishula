#!/usr/bin/env python3
"""Oracular recomputation of ban_conformance_fixtures.yaml — TR-09.

An INDEPENDENT Python implementation of §13.3 (not the Go code under
test). It walks every fixture's steps exactly as the Go runner will,
recomputes each expectation from the §13.3 formulas, and validates the
fixture file's structure. Exits non-zero on the first mismatch.

This is why no expectation in the YAML is hand-tuned: the Go runner
recomputes them from these formulas at test time, and this script —
written before the Go implementation exists — is the independent check
CI runs beside the Go suite so the two can never drift silently.

Expected values this pins (derived, not asserted by hand):
  λ            = ln2/(decayHalfLifePct/100 · findtime) = ln2/120 s^-1
  score(s, t)  = Σ w_i · e^(−λ·(t − t_i))   over window (age ≤ findtime)
  until(r)     = min(bantime · backoff^r, maxBantime)
"""
import math
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "ban_conformance_fixtures.yaml")

# §13.3 constants — byte-mirror of the BanPolicy CRD sketch (§19.1).
FINDTIME = 600
THRESHOLD = 10
BANTIME = 600
BACKOFF = 2
MAXBANTIME = 86400
HALF_LIFE_PCT = 20
WEIGHTS = {
    "crsCritical": 5,
    "crsWarning": 2,
    "botConsensus": 4,
    "botSingle": 1,
    "rateBreach": 3,
    "schemaViolation": 2,
    "authFailure": 2,
    "kernelBurstFlag": 3,
}

LAMBDA = math.log(2) / (HALF_LIFE_PCT / 100.0 * FINDTIME)  # ln2 / 120 s


def decayed(weight, age):
    """§13.3: w · e^(−λ·age); λ from the decayHalfLifePct half-life."""
    return weight * math.exp(-LAMBDA * age)


def until_for(recid):
    """§13.3: min(B · κ^recid, Bmax)."""
    return min(BANTIME * BACKOFF**recid, MAXBANTIME)


def expected_score(events, at):
    """§13.3 score: Σ w·e^(−λ·(t_now−t_i)) over the sliding window.

    Retention: an event stays in the window while age ≤ findtime.
    events: [(t, kind)].
    """
    return sum(
        decayed(WEIGHTS[k], at - t) for (t, k) in events if 0 <= at - t <= FINDTIME
    )


def fixture_check(fx):
    """Recompute one fixture's expectations; return (fails, notes)."""
    fid = fx["id"]
    fails, notes = [], []
    events = []      # this fixture's (t, kind) sequence
    until = None     # live ban expiry (None = never banned)
    recid = 0        # completed ban transitions so far
    prev_score = None

    for step in fx["steps"]:
        if "expectNoEnforcement" in step:
            continue  # structural only — the Go runner owns the enforcement surface
        at = step["at"]
        if "ingest" in step:
            ing = step["ingest"]
            events.append((at, ing["kind"]))
        elif "evaluate" in step:
            ev = step["evaluate"]
            s = expected_score(events, at)
            notes.append(f"{fid}@{at} score={s!r}")

            if ev.get("strictDecay") and prev_score is not None and not s < prev_score:
                fails.append(f"{fid}@{at}: strictDecay asserted but {s} >= {prev_score}")
            if "wantWouldBan" in ev:
                if until is not None and at < until:
                    got = False  # §13.3 step 2: active ban, no re-scoring
                else:
                    got = s >= THRESHOLD
                if got != ev["wantWouldBan"]:
                    fails.append(
                        f"{fid}@{at}: wantWouldBan={ev['wantWouldBan']} oracle {got} (score {s:.6f})"
                    )
                if ev.get("banTransition"):
                    want = ev.get("wantUntil")
                    exp = at + until_for(recid)
                    if want is not None and want != exp:
                        fails.append(f"{fid}@{at}: wantUntil={want} oracle {exp}")
                    recid += 1
                    until = exp
            state = ev.get("state")
            if state == "ACTIVE_BAN" and not (until is not None and at < until):
                fails.append(f"{fid}@{at}: ACTIVE_BAN asserted but no live ban (until={until})")
            if state == "CLEAR" and until is not None and at < until:
                fails.append(f"{fid}@{at}: CLEAR asserted while ban live until {until}")
            prev_score = s
        elif "banAt" in step:
            b = step["banAt"]
            s = expected_score(events, at)
            if s < THRESHOLD:
                fails.append(f"{fid}: banAt@{at} but oracle score {s:.6f} < threshold")
            until = at + until_for(recid)
            want = b.get("wantUntil")
            if want is not None and want != until:
                fails.append(f"{fid} banAt@{at}: wantUntil={want} oracle {until}")
            recid += 1
            notes.append(f"{fid} banAt@{at} until={until}")
        elif "expectNoEnforcement" in step:
            pass  # structural only — the Go runner owns the enforcement surface
        else:
            fails.append(f"{fid}: unknown step shape {sorted(step)}")
    return fails, notes


def main():
    with open(FIXTURES) as f:
        doc = yaml.safe_load(f)

    assert doc["schema"] == "trishula.ban-conformance.v1"
    pol = doc["policy"]

    # §19.1 sketch byte-mirror (constants + weight names verbatim)
    assert pol["constants"] == {
        "findtime": "10m", "threshold": 10, "bantime": "10m",
        "backoff": 2, "maxBantime": "24h",
    }, pol["constants"]
    assert pol["weights"] == WEIGHTS
    assert pol["decayHalfLifePct"] == 20
    assert pol["prefixEscalation"] == {"enabled": False, "minKeys": 8, "window": "10m"}
    assert pol["mode"] == "shadow"  # §13.3 shadow-first

    fails, notes = [], []
    n_walked = 0
    for fx in doc["fixtures"]:
        if fx.get("reserved"):
            continue
        if fx["id"] == "F11":
            sched = fx.get("backoffSchedule")
            if not sched:
                fails.append("F11: missing backoffSchedule")
                continue
            for k, want in zip(sched["recidivism"], sched["bantime"]):
                exp = until_for(k)
                if want != exp:
                    fails.append(f"F11 k={k}: want {want} oracle {exp}")
            continue
        n_walked += 1
        f2, n2 = fixture_check(fx)
        fails += f2
        notes += n2

    # --- spot checks, independent of the walk --------------------------------
    f = lambda w, age: w * math.exp(-LAMBDA * age)
    # F09: after expiry (until 602), one fresh crsCritical@603 must NOT
    # re-cross: stale remainder (5·e^(−λ·602), the t=1 event is still inside
    # the window at age 602) + 5 < 10
    f9 = f(5, 602) + 5
    if f9 >= THRESHOLD:
        fails.append(f"F09 spot: remainder+fresh = {f9} must stay < {THRESHOLD}")
    # F10's second crossing: 3 crsCritical at 700/701/702 ≈ 14.91 ≥ 10
    f10 = 5 + f(5, 1) + f(5, 2)
    if f10 < THRESHOLD:
        fails.append(f"F10 spot: second-cross score {f10} must reach the threshold")

    if fails:
        print("ORACLE MISMATCHES:")
        for m in fails:
            print(" -", m)
        return 1
    print(
        f"oracle ok: {n_walked} walked fixtures + F11 schedule row; "
        f"{len(notes)} expectations recomputed from PRD §13.3 "
        f"(λ=ln2/{int(HALF_LIFE_PCT/100*FINDTIME)}s, T={THRESHOLD}, "
        f"until=min(B·κ^r, {MAXBANTIME}))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
