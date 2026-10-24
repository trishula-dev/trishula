# lab/module-3 — the eBPF platform lab (TR-27b)

The module-3 lab shows packets meeting programs: the wire contracts of
the kernel plane, the XDP attach lifecycle, and the full ban verdict
path in kernel. The doc side of the module:
[docs/academy/module-3.md](../../docs/academy/module-3.md). The spec
surfaces: [§7.1 Module 3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches)
and [§9](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#9-ebpf-packet-path).

## Run it

```bash
bash lab/module-3/run.sh
```

| Leg | Surface | The gate |
|---|---|---|
| wire | `go test -count=1 -v ./internal/shield/` over the wire-contract, verdict-semantics and tier tests | every pinned contract holds (ban entry layout, v4 wire, reason codes, kernel contract, tier classes) |
| attach | [`lab/verify-xdp-chain.sh`](../verify-xdp-chain.sh) `eth0` — CO-RE compile, verifier load, pin, XDP attach, detach | `XDP-CHAIN-OK` |
| ban-e2e | `go test -tags ban_e2e -count=1 ./test/banenforce/` | ban publish → kernel drop (TC_ACT_SHOT) → expiry auto-lift → reconciler lift → evidence JSONL |

The attach and ban-e2e legs need a Linux kernel: root, BTF at
`/sys/kernel/btf/vmlinux`, BPFFS at `/sys/fs/bpf`. The repo's kernel
evidence posture is an in-VM run; on a macOS host the lab drives the
kernel legs inside an OrbStack VM.

## The kernel legs on a macOS host

```bash
TRISHULA_LAB_VM=trishula-build-dev bash lab/module-3/run.sh
```

The lab maps the checkout into the VM (`/Users/...` →
`/mnt/mac/Users/...`, the OrbStack mount) and runs the attach script
and the tagged e2e inside the VM, as root. A missing or insufficient
kernel environment prints a loud SKIP line; no leg ever reports a skip
as a pass.

## Knobs

| Knob | Default | Meaning |
|---|---|---|
| `TRISHULA_ROOT` | the script's grandparent | the repo checkout the legs use |
| `TRISHULA_LAB_VM` | empty | the OrbStack VM name for the kernel legs (kernel legs SKIP without it on a non-Linux host) |
| `TRISHULA_VM_ROOT` | the `/Users` → `/mnt/mac/Users` map | the repo path inside the VM |
| `TRISHULA_VM_BPFTOOL` | the linux-tools build | the VM bpftool path (the default bpftool sits version-mismatched against the OrbStack kernel; the repo [AGENTS.md](../../AGENTS.md) note) |
| `VM_IFACE` | `eth0` | the interface the attach leg uses inside the VM |

## CI surface

The nightly job (`module-3-ebpf-lab` in
[`.github/workflows/lab-nightly.yml`](../../.github/workflows/lab-nightly.yml))
runs the same script on a hosted runner: the wire leg passes there; the
kernel legs SKIP (hosted runners carry no kernel-test VM). The kernel
gates' home is the developer VM posture — the same posture
[`lab/verify-xdp-chain.sh`](../verify-xdp-chain.sh) documents.

## Evidence

Transcripts in PR bodies and issue records quote verbatim run output.
The recorded module-3 lab runs sit on the TR-27b record (issue
[#170](https://github.com/trishula-dev/trishula/issues/170)).
