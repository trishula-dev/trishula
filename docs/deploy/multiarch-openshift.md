# Multi-arch builds and OpenShift compatibility (TR-33)

TR-33 moves the OpenShift and multi-arch builds into the evaluation and build
lanes ([spec §20.2 Phase 1+](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#202-phasing)).
This page carries the build statement, the CI lane and the OpenShift
compatibility notes. Hardware- and cluster-gated rows read `PENDING` — the
CI environment cannot reach them, and this page never reads a pending row as
green.

## The multi-arch build statement

**What builds cross-arch today.**

- Every eBPF program compiles for both arms. bpf2go generates one object per
  arm at generation time
  ([§19.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#191-stage-sketches-from-the-code-v0-poc)),
  and the repo commits both objects for all 8 programs. The census: 16 objects
  = 8 programs x 2 arms.
- The `go:generate` directives carry two shapes. `-target amd64,arm64`
  (route_mark, residue_shield, residue_flow) pins both arms in the directive.
  `-target native` (bpf_shield, ingest_flow, ban_enforce, tier_probe,
  tier_xdp) generates the host arm; the committed pair carries the census for
  it.
- Every command cross-compiles. `GOOS=linux GOARCH=amd64 go build ./...` and
  `GOOS=linux GOARCH=arm64 go build ./...` exit clean; the loader files carry
  per-arm `go:build` tags and `go:embed` the matching object, so a missing arm
  fails the compile, not only the census.
- The engine and the other commands carry no arm-specific code paths. The
  shield loaders select the object by build tag at compile time.

**What the release manifest needs per arch.**

- The release asset set carries one object per program per arm plus
  `checksums.txt`. The 2026.01-rc3 shape: 16 objects + checksums.txt. The
  asset name is the object base name.
- `release-attest.yml` attests every asset with build provenance and the SBOM,
  so the attest surface verifies a per-arm asset set with no change.
- `multiarch-build.yml` asserts the census on every build-surface change. A
  single-arm program fails CI before a release carries the one-arm asset set.

**PENDING — the release manifest beyond the object set:**

- Command binaries per arch as release assets. The objects carry this today;
  the binaries need the later image lane. `PENDING`.
- The OCI image index per arch (one manifest list over amd64 + arm64 tags).
  The image build lane records it. `PENDING`.
- The DPU (BlueField-class) shield port: its own evaluation
  ([#32](https://github.com/trishula-dev/trishula/issues/32)). `PENDING`.

## The CI lane

`.github/workflows/multiarch-build.yml` runs the statement on every pull
request that touches the build surfaces, and on demand:

1. Cross-compiles every command for linux/amd64 and linux/arm64.
2. Asserts the object census: every committed x86 object carries the arm64
   twin in the same directory, and vice versa.

## OpenShift compatibility notes

**What carries over today.**

- The objects are CO-RE: one committed object per arm covers the kernel
  version range the relocations carry. The loader runs cilium/ebpf against the
  target kernel's BTF.
- The arm64 node fleet is covered: the committed arm64 objects plus the arm64
  cross-compile carry the same programs the amd64 fleet runs.
- The engine is a plain Go binary. A Deployment on either arm works once the
  image lane carries per-arch images.

**PENDING — cluster-gated rows (no OpenShift estate in reach of this
environment):**

| Row | The gate it needs |
| --- | --- |
| Shield DaemonSet under the OpenShift SCC model | An OpenShift estate grants the shield's service account the privileged SCC (or the CAP_BPF + CAP_NET_ADMIN posture). The XDP/TC attach runs green. |
| RHCOS kernel surface | BTF present on the RHCOS kernel; the CO-RE load and the attach leg run green. |
| Attach interface on OVN-Kubernetes | The shield binds the estate's primary interface (the name differs per CNI and per platform). The TC leg drains flow events. |
| Ban-table pin visibility | The bpffs pin surface on the OpenShift node image holds the shield pins. The ban E2E leg runs green. |

The rc ladder carries OpenShift and multi-arch in the tracked evaluations of
the 2026.01 release notes. Each `PENDING` row above closes with its gate
output filed against this issue.
