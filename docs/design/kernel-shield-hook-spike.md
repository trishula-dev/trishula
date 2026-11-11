# The kernel shield hook spike — design-note scaffold (issue #292)

> **Trishula design note — the hosted-runner hook spike scaffold.**
> Parent record: [issue #292](https://github.com/trishula-dev/trishula/issues/292) — the build requirements RFC.
>
> **Spec refs:** [the two-plane principle](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle) ·
> [enforcement tiers](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#134-enforcement-actions-by-tier) ·
> [phasing](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#202-phasing)

Status: scaffold. This note ships the spike mechanism and the results-table
schema. The results are PENDING. The recorded-run receipt does not exist yet.
The PR CI run of the spike workflow has not happened. The fill belongs to
issue #292 after that run lands. The note prints no measured value.

Wave row: TR-205, lane C. The deliverables: the spike workflow and this note.

## 1. The question the spike answers

Rule: the spike records one load state per shield hook class, on one
hosted-runner kernel, inside a privileged pod.

The shield's kernel plane carries 4 hook classes. Each class ships as one
committed bpf2go object per arm. The census guard holds the
1-program-per-arm pairing. The x86 object is the runner arm. The table is
the spike inventory:

| hook class | program | SEC | source | committed x86 object |
| --- | --- | --- | --- | --- |
| XDP shield | `shield_xdp` | `xdp` | `bpf/shield_xdp.c` | `internal/shield/bpf_shield_x86_bpfel.o` |
| XDP ban | `ban_xdp` | `xdp` | `bpf/ban_xdp.c` | `test/banenforce/ban_enforce_x86_bpfel.o` |
| TC flow | `tc_ingress_waf` | `tc` | `bpf/flow_tc.c` | `internal/engine/ingest/ingest_flow_x86_bpfel.o` |
| TC route | `route_mark` | `tc` | `bpf/route_mark.c` | `internal/fastpath/routetemplate/route_mark_x86_bpfel.o` |

## 2. What the spike does not claim

Rule: a spike result covers one kernel, and it measures loads only.

- One result covers one kernel build on one hosted-runner generation.
- The spike records load state. It attaches no program to an interface. It
  sends no traffic.
- A `LOADED` row asserts nothing about cluster kernels (OpenShift RHCOS) or
  DPU kernels. Cluster and hardware lanes gate those kernels separately.
- The spike prints no performance number.

## 3. The mechanism

Rule: the probe loads the committed release objects through the production
load library. The loads run inside a privileged pod on the runner kernel.

The spike workflow ([../../.github/workflows/shield-hook-spike.yml](../../.github/workflows/shield-hook-spike.yml))
triggers on every pull request and on `workflow_dispatch`. Steps:

1. The job records the runner environment first. The record carries
   `uname -a`, the runner image tag (`ImageOS`/`ImageVersion` verbatim),
   the `PRETTY_NAME` line and the docker version. A later-step failure
   still leaves this evidence.
2. The job builds `cmd/shield-hook-spike` under the `shield_hook_spike`
   build tag. The tag keeps the probe out of every other build.
3. The job runs the probe in a `--privileged` pod on the `ubuntu:24.04`
   image, with the checkout mounted read-only. The pod shares the runner
   kernel. The loads run against that kernel.
4. The probe loads each committed object with `github.com/cilium/ebpf` —
   the same load library the production loaders use. It selects the hook's
   program by name, never by position. It closes every collection before
   exit.
5. The probe writes the summary table and the verbatim record. The job
   publishes both: the job summary and the `shield-hook-spike` artifact.

Mechanism facts:

- The probe creates no pins. Every collection closes before exit. The
  spike leaves no kernel residue.
- Each row records the object `sha256` fingerprint and its byte size. A
  stale object pair reads about 3x the stripped size. The fingerprint
  catches that on the receipt before any verdict gets read.
- The pod shell records `uname -a` and the BTF check line (`ls -l
  /sys/kernel/btf/vmlinux`) verbatim before the probe starts.

Exit codes (the red-run rules):

- `0` — the spike recorded at least one load state. A per-hook `FAIL` row
  is a recorded result, not a CI failure.
- `2` — the kernel environment lacks root or BTF. No evidence exists.
- `3` — zero hook classes loaded. The kernel environment carries an
  anomaly (module, caps or BTF loss).

## 4. How to read the results table

Rule: one row per hook class; every column carries one meaning.

| column | meaning |
| --- | --- |
| `hook (program)` | the program entrypoint name |
| `attach type` | the SEC altitude (`xdp` or `tc`) |
| `source` | the C source of the hook |
| `committed object` | the release artifact the probe loaded |
| `load state` | `LOADED`, or `FAIL(step)` for the failed step |
| `load error` | the first line of the verbatim error, truncated; the full error sits in the details block and the artifact |
| `min kernel features` | the feature set the hook class needs on kernels where its load fails; the post-run fill sets the cell (issue #292, row 4) |
| `notes` | the object fingerprint, the byte size, the map count, the named-program check |

The `min kernel features` column sits in the schema before any run. The
fill reads the verbatim error into the minimal feature set. Release nodes
check that set (issue #292, row 4).

The artifact `shield-hook-spike.txt` carries the verbatim record. The
record holds, with no truncation:

- the kernel version and the runner image tag.
- the pod `uname -a` line and the BTF check line.
- the pod image digest.
- every load error, from first byte to last.

The CI rule: a `FAIL` row leaves the job green, so one kernel fact never
breaks a pull request. The job turns red only under the exit-code rules
of section 3. That keeps one red signal for the mechanism, not one per
kernel fact.

## 5. The pinned-recommendation fields

Rule: the run records the kernel and image values that pin the CI runner
image for this job.

The probe emits a `Pinned-recommendation fields` table into the job
summary. The fields:

- the kernel class, the kernel release and the full kernel version line.
- the runner image tag (`ImageOS`/`ImageVersion` verbatim).
- the pod image with its digest.
- the go toolchain.

The post-run fill reads these fields into the runner-image pin for the CI
gate (issue #292, row 3).

## 6. Results

Rule: this section carries the recorded run receipt and the fill. The receipt
re-reads at each future spike run; a future run posts a fresh table.

- Owner: issue #292.
- Receipt: PR #297 head, run
  [42932662527](https://github.com/trishula-dev/trishula/actions/runs/42932662527)
  (2026-11-11, the `ubuntu:24.04` privileged pod on the runner kernel).
  Artifact: `shield-hook-spike` (the full verbatim record).
- The runner pair the receipt records: kernel `7.0.0-1019-azure`, runner image
  `ubuntu26/20261101.186.1`, pod image `ubuntu:24.04`, BTF present
  (7267528 bytes). The pair floats with the hosted image; every spike run
  re-records it, and the fresh run receipt re-links here.
- The result: 4 of 4 hook classes load on the hosted runner kernel. The
  per-PR legs run on hosted runners; no separate kernel-node pool is
  required for the CI tiers. The release-stage node requirement reduces to
  the runner-default set: a kernel with BTF and privileged containers.

| hook (program) | load state | error (truncated) | min kernel features |
| --- | --- | --- | --- |
| shield_xdp (xdp) | LOADED | — | runner defaults (BTF present) |
| ban_xdp (xdp) | LOADED | — | runner defaults (BTF present) |
| tc_ingress_waf (tc) | LOADED | — | runner defaults (BTF present) |
| route_mark (tc) | LOADED | — | runner defaults (BTF present) |

The object-level provenance from the receipt (sha256 short / size pairs):
`shield_xdp 78d3b14fdf81/10816 B`, `ban_xdp cad16bcff92e/5656 B`,
`tc_ingress_waf 1eaa7bc2dcb1/113128 B`, `route_mark b43fdcc18278/10072 B`.
A future size delta over ~3x names a stale pair before any load attempt.
