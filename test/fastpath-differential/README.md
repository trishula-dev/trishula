# test/fastpath-differential — the TR-40d shadow differential harness

The socket-plane shadow differential [leaf of TR-40, issue
#190](https://github.com/trishula-dev/trishula/issues/190): the fast-path decision
stream shadow-runs against the engine verdict stream on one committed corpus. The
run reports the match census, the shape inventory and the mismatch budget. The
design record: [`docs/design/socket-plane/4-compiler-census.md` section
10](https://github.com/trishula-dev/trishula/blob/main/docs/design/socket-plane/4-compiler-census.md)
and the slow-path limitation list in its section 11. No enforcement claim and no
wall ride this package: the census records verdicts, never timings.

## The two streams

| Stream | Surface |
| --- | --- |
| fast path | the route template semantics per synthetic frame: header checks, the bounded request-line scan, the LPM row match, the action. Kernel-free host: the userspace projection (`model.go`). Kernel leg: the committed `route_mark` object under the test-run harness. |
| engine | the loaded bundle (`internal/operator` Compile → Load → Eval) over the case view; the staged template rows carry the compiled row truth. |

The match criterion (four rows: both streams resolve; every drop carries compiled
drop-row backing; every miss reads forward with no mark; kernel fidelity). The
plane-split differences are reported, never scored — the engine stays the detection
authority.

## Layout

```
test/fastpath-differential/
  corpus/*.yaml              19 cases, 6 shape classes (name-ordered load, strict schema)
  runner.go                  corpus loader + engine stream ( Compile/Load/Eval + Stage ) + projection classes
  model.go                   the userspace projection of the committed template + the frame builder
  budgets.go                 the mismatch budget rows + the budget verdict rule
  diffgate_test.go           the kernel-free gate: census + budget read + the class-coverage gate
  e2e_diff_linux_test.go     the kernel leg: linux build tag + fastpath_diff_e2e job tag + root/euid skip gate
```

## How to run

Kernel-free gate (host CI runs this; it reports the census):

```bash
go test ./test/fastpath-differential/ -count=1 -v
```

Kernel leg (a Linux host, root, BTF; skips read fails under REQUIRED):

```bash
sudo env PATH="$PATH" HOME="$HOME" FASTPATH_DIFF_E2E_REQUIRED=1 \
  go test -tags fastpath_diff_e2e -v ./test/fastpath-differential/
```

The kernel leg runs the committed object through BPF_PROG_TEST_RUN over the TC
program; it never attaches. The test-run surface returns the TC action only, so the
kernel leg scores the decision outcome — the skb mark stays a userspace-leg pin.

## Pinned results (the branch's GREEN commit; stable across 3 runs per leg)

Kernel-free gate census:

```text
fastpath-differential census: cases 19, ran 19, skipped 0
fastpath-differential census: parity 19/19, pinned deltas 0
fastpath-differential census: shapes drop-row 5 forward-row 6 miss 8 malformed-frame 4 size-quirk 2 nul-shape 2
fastpath-differential census: plane-split 5 (drop-vs-nondecisive 4, forward-vs-decisive 1)
fastpath-differential budget row unexplained: live 0, holds
fastpath-differential budget row failopen-drop: live 0, holds
fastpath-differential budget row unresolved-engine: live 0, holds
fastpath-differential budget row kernel-fidelity: live 0, holds
fastpath-differential budget row plane-split: live 5, holds
```

Kernel census (dev VM, ubuntu 24.04 arm64, kernel 7.0.14-orbstack-00380-ga7e0a2dc9535):

```text
fastpath-differential kernel census: frames 19, fidelity 19/19, deltas 0
fastpath-differential budget row kernel-fidelity: live 0, holds
```

## The mismatch budget

| Class | Recorded | Budget | Reads |
| --- | --- | --- | --- |
| unexplained | 0 | 0 | gate |
| failopen-drop | 0 | 0 | gate |
| unresolved-engine | 0 | 0 | gate |
| kernel-fidelity | 0 | 0 | gate |
| plane-split | 5 | 5 | reported; re-pin with a fresh recorded run, maintainer only |

The watched RED pair: the RED commit held the plane-split row unrecorded and one
hand-derived pin wrong (the leading-space case); the live walk corrected both and the
GREEN recorded the census.
