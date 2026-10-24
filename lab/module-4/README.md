# lab/module-4 — the security-modeling lab (TR-27c)

The module-4 lab executes the security-modeling lessons: the three
rate algorithms, the ScoredWindowBan v1 oracle, the bot detector
families, and the verdict records. The doc side of the module:
[docs/academy/module-4.md](../../docs/academy/module-4.md). The spec
surfaces: [§7.1 Module 4](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches),
[§7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules)
(interactive rate fixtures) and
[§13](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#13-rate-limiting-dos-response--temporary-bans).

## Run it

```bash
bash lab/module-4/run.sh
```

| Leg | Surface | The gate |
|---|---|---|
| rate-algorithms | `go test -v ./internal/engine/rateban/` over the token bucket, sliding window, EWMA and key-composition tables | every named row holds (the interactive fixtures of the rate lesson) |
| ban-ladder | `go test -v ./test/ban-conformance/` — the ScoredWindowBan v1 oracle over [`ban_conformance_fixtures.yaml`](../../test/ban-conformance/ban_conformance_fixtures.yaml) | the spec algorithm reproduces from the fixture set alone |
| fingerprints | `go test -v ./internal/engine/botdef/` over the header fingerprint and behavior-window tests | browser vs tool shapes classify apart; the merge policy holds |
| verdict-records | `cmd/attackdemo`: the seed rate rule at 39/40/41 per 5m, and the BOLA decision record | the rule flips exactly at the `> 40` boundary; the `verdict.v1` record prints both ways |
| kernel-ban | `go test -tags ban_e2e ./test/banenforce/` — the L2 enforcement tier | threshold-cross → kernel drop (TC_ACT_SHOT) → expiry → evidence JSONL |

## The kernel leg on a macOS host

```bash
TRISHULA_LAB_VM=trishula-build-dev bash lab/module-4/run.sh
```

The lab maps the checkout into the VM (`/Users/...` →
`/mnt/mac/Users/...`, the OrbStack mount) and runs the tagged ban e2e
inside the VM, as root. The kernel leg needs Linux with root, BTF and
BPFFS; without it the leg prints a loud SKIP line. No leg ever reports
a skip as a pass. The same gate documents under
[`lab/module-3/README.md`](../../lab/module-3/README.md).

## Knobs

| Knob | Default | Meaning |
|---|---|---|
| `TRISHULA_ROOT` | the script's grandparent | the repo checkout the legs use |
| `TRISHULA_LAB_VM` | empty | the OrbStack VM name for the kernel leg |
| `TRISHULA_VM_ROOT` | the `/Users` → `/mnt/mac/Users` map | the repo path inside the VM |

## CI surface

The nightly job (`module-4-modeling-lab` in
[`.github/workflows/lab-nightly.yml`](../../.github/workflows/lab-nightly.yml))
runs the same script on a hosted runner: legs 1-4 pass there; the
kernel leg SKIPs (hosted runners carry no kernel-test VM). The ban
oracle and the rate tables already run in every pull request: the
go-build workflow carries `go test ./...`.

## Evidence

Transcripts in PR bodies and issue records quote verbatim run output.
The recorded module-4 lab runs sit on the TR-27c record (issue
[#171](https://github.com/trishula-dev/trishula/issues/171)).
