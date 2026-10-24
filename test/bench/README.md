# test/bench — the §17 benchmark harness (TR-24)

This package is the in-repo part of the [spec §17.2 benchmark plan](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#172-benchmark-plan).
It encodes the [§17.1 budget table](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#171-budgets-by-stage)
as data, measures the engine-side scenarios the hosted CI can run, and
gates the measurements.

## What the harness carries

- The §17.1 budget table as typed rows: stage id, p99 bound, optional
  p50 bound, enforcer. The kernel-cache line encodes as its two stated
  regimes. The end-to-end hop row carries the §21 M2 mark.
- The §17.2 scenario inventory: all nine rows with a plane value and,
  where CI cannot run them, the absent runtime they wait on.
- Request recipes for the driveable rows: deterministic bodies, a fixed
  peer scope, bounded iteration counts (seconds of CI time, total).
- The nearest-rank p50/p99 estimator and the budget + regression gate.
  The gate carries the §17.2 rule: a p99 regression over 10% from the
  recorded baseline fails.

## How to run

Run the guards (part of every CI run):

```bash
go test ./test/bench/ -count=1 -v
```

Run the benchmark surface for benchstat-style comparison:

```bash
go test ./test/bench/ -bench . -run '^$'
```

## The driveable scenarios in CI

- Inline idle (§17.2 row 2): clean GET through the CRS walk. Guard: no
  interruption, no phase-2 match.
- Inline steady (§17.2 row 3): the 8KB full-CRS cell the M2 metric
  binds, plus the two attack shapes. Guards: phase-2 matches present;
  p99 inside the M2 envelope.
- Body-size ladder (§17.2 row 7): JSON at 1 KB, 8 KB, 64 KB plus the
  two arg-dense urlencoded shapes.

The guard pins the measured verdict set with margin rules: cells that
read at least 4x over their budget row are pinned unmet; the other
cells carry a 4x blowup bound. A green run with a missing pin is a
moved finding: re-pin with the fresh recorded run.

## How the live verdicts settle (TR-92a)

The budget verdict pairs the machine factor around every budget-row
pair: one sample before the recipe measures, one after. A sample reads
the runner speed on a fixed calibration probe (wall time over CPU
time). Engine cost cannot move the probe; runner motion moves it. The
verdict classes:

- Both samples read inflation (each at or above 1.5). The pair
  brackets the row's window. The agreed level (the pair mean)
  normalizes the walls. The row reads unmet when the normalized p99
  still misses; else it reads retained-with-variance.
- One sample reads inflation. The pair cannot settle code evidence. A
  raw miss records retained-with-variance and the run continues; raw
  walls that hold read holds.
- Neither sample reads inflation. The raw verdict stands: the row
  reads unmet only when the raw budget row genuinely misses.

Budgets, pins and fixtures stay unchanged. The storm record (#147): a
calibration once per run printed 1.00 while the sustained concurrent
CI load inflated the walls, and rows misclassified unmet. The per-recipe
pair makes the runner state visible per row and the verdict classes
keep the gate variance-consistent. A real regression still reads unmet:
quiet pairs leave the raw verdict standing, and agreed inflation leaves
the normalized verdict standing.

Why the strict M2 bound does not gate this suite: hosted CI runs test
packages in parallel and shared runners carry sibling load, so a
strict 1.5 ms p99 assert reads 2x to 7x tails under contention
(recorded: 3.5 ms on the same code that reads 0.45x in a quiet run).
The live guard records the strict M2 verdict per run and gates the
4x band. The strict M2 blocking + the 10% regression rule gate on a
dedicated sequential bench job with a recorded baseline — follow-up
work, listed in the harness remainder.

## Recorded run (this host, 2026-10-23, go1.27.2 arm64, at the RED commit sha)

Output of `go test ./test/bench/ -run TestBudgetVerdictsOnLivePath -v`,
MEASURED lines verbatim:

```text
MEASURED idle-get                n= 400 size=     0 B p50=   113.3 us p99=    308.1 us budget=engine-inspect-8k      (600 us) factor=0.51x
MEASURED steady-json-8k          n= 240 size=  8163 B p50=   123.5 us p99=    319.7 us budget=e2e-inline-hop-8k      (1500 us) factor=0.21x
MEASURED attack-xss-small        n= 300 size=    31 B p50=   341.5 us p99=    679.5 us budget=e2e-inline-hop-8k      (1500 us) factor=0.45x
MEASURED attack-sqli-small       n= 300 size=    17 B p50=   288.8 us p99=    651.5 us budget=e2e-inline-hop-8k      (1500 us) factor=0.43x
MEASURED ladder-json-1k          n= 300 size=  1003 B p50=   118.1 us p99=    283.5 us budget=engine-inspect-8k      (600 us) factor=0.47x
MEASURED ladder-json-8k          n= 240 size=  8163 B p50=   119.8 us p99=    313.7 us budget=engine-inspect-8k      (600 us) factor=0.52x
MEASURED ladder-json-64k         n= 120 size= 65519 B p50=   126.3 us p99=    404.7 us budget=engine-inspect-64k     (1200 us) factor=0.34x
MEASURED ladder-form-dense-1k    n=  16 size=  1019 B p50=  5422.2 us p99=   6451.6 us budget=engine-inspect-8k      (600 us) factor=10.75x
MEASURED ladder-form-dense-8k    n=  10 size=  8189 B p50= 46683.0 us p99=  48842.7 us budget=engine-inspect-8k      (600 us) factor=81.40x
```

## What the run records

The verdicts, against the §17.1 budget rows:

| Cell | p50 | p99 | Budget row p99 | Verdict |
| --- | --- | --- | --- | --- |
| idle GET | 113.3 µs | 308.1 µs | 600 µs | holds (0.51x) |
| 8 KB JSON post, full CRS | 123.5 µs | 319.7 µs | 1.5 ms (M2) | holds (0.21x) |
| XSS attack post | 341.5 µs | 679.5 µs | 1.5 ms (M2) | holds (0.45x); p50 over the 300 µs row bound |
| SQLi attack post | 288.8 µs | 651.5 µs | 1.5 ms (M2) | holds (0.43x); p50 over the 300 µs row bound |
| 1 KB JSON | 118.1 µs | 283.5 µs | 600 µs | holds (0.47x) |
| 8 KB JSON | 119.8 µs | 313.7 µs | 600 µs | holds (0.52x) |
| 64 KB JSON | 126.3 µs | 404.7 µs | 1.2 ms | holds (0.34x) |
| 1 KB arg-dense form | 5422.2 µs | 6451.6 µs | 600 µs | UNMET (10.75x) |
| 8 KB arg-dense form | 46683.0 µs | 48842.7 µs | 600 µs | UNMET (81.40x) |

The open finding: the arg-dense urlencoded deep-inspect surface reads
at least 10x over the engine-inspect-8k budget row. The cost scales
with the argument count, not the byte count: a 491-byte body with
64 arguments read over 4x the 600 µs row in the probe runs. The p50
bound of the M2 row stays open: the CI cells carry no direct-baseline
(harness runs the reference evaluator alone; the e2e p50 needs the
direct-to-pool baseline of §17.2 row 1 in the NGF lab).

## What stays outside this harness

- Rows 1, 4, 5, 9 wait on the NGF lab and the kernel plane (the
  inventory names the absent runtime per row). No CI stub fakes them.
- Row 8 waits on the ML tier. Row 6 runs nightly on bare metal.
- The §17.2 CI leg for the 10% regression rule: the gate logic ships
  here and the guard proves it; the wired CI job with a recorded
  baseline and per-runner calibration is follow-up work.
- The engine-side CI bound covers the CRS reference path. The S0 CEL
  slot and the full ladder walk join when the harness wires their
  evaluators.
