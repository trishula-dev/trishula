# Academy Module 2 — TLS & QUIC

Module 2 of the teach-the-web curriculum. The curriculum map entry
lives in
[spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches).
The pedagogy rules live in
[spec §7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules).
The deliverable set lives in
[spec §7.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#73-deliverables).

Spec §7.2 fixes one pedagogy rule for this page: every rule example
cites its wire anatomy. Wire anatomy is the record of the bytes a
surface reads. For Module 2 that record is the ClientHello. Each
lesson names the exact fields it reads.

## The lessons

| # | Topic | The bytes on the wire |
|---|---|---|
| 1 | The handshake | the ClientHello: SNI, ALPN, ciphers, extensions |
| 2 | Termination | who ends TLS, and what each plane sees after |
| 3 | JA4/JA4S | one fingerprint from the visible hello bytes |
| 4 | Surfaces today | the shipped pins, and the missing extract (PENDING) |
| 5 | QUIC and 0-RTT | the UDP move, and the replay risk |
| 6 | Rule anatomy | the fields each surface reads, and the walls |
| 7 | The lab | golden vectors, header shapes, the DX1 termination read |

## Lesson 1 — the handshake: the ClientHello

A TLS 1.3 connection opens with two flights in the clear. The
ClientHello opens the first flight. The hello carries:

- the SNI extension — the server name the client asks for.
- the ALPN list — the protocols the client offers, in offer order.
- the cipher suites and the extensions, in offer order.

After the two flights the record layer encrypts the application data.
The hello fields stay the one visible part of the connection. Hold
that fact: the fingerprint lesson stands on it.

The in-repo summary shape is
[`ClientHelloSummary`](../../internal/engine/botdef/ja4.go): transport,
legacy version, SNI, ALPN, ciphers, extensions, signature algorithms.
The struct mirrors the visible hello fields, in offer order.

## Lesson 2 — termination: who ends TLS, and what each plane sees

The gateway owns TLS termination in the reference deployment
([spec §10.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#102-the-contract-trishula-as-a-gateway-api-citizen)).
The listener carries `tls.mode: Terminate`. The engine sees plaintext
after the gateway hop. The DX1 topology runs the same shape.

Two boundaries follow from
[§6.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#63-non-goals-v1):

- The product is not a TLS-terminating edge proxy for the whole estate.
  The gateway owns the handshake in the reference deployment.
- Engine-side termination is a secondary, feature-gated mode. v1 does
  not ship it.

The two planes see different bytes (Module 3, lesson 1). The shield
sees record bytes at the NIC. The ClientHello rides the cleartext
first flight; the application data after it is ciphertext. The engine
sees post-termination plaintext. Name the altitude before any
detection claim.

## Lesson 3 — JA4/JA4S: one fingerprint from the visible hello

FoxIO JA4 hashes the visible hello fields. The string carries three
parts: `t13d1516h2_8daaf6152771_e5627efa2ab1`.

- Part 1: the transport code, the TLS version, the ALPN code.
- Part 2: a sha256 over the sorted cipher list, truncated.
- Part 3: a sha256 over the sorted extension list, truncated.

GREASE values leave the counts and the hashes before scoring. The
a-section code takes the first ALPN offer. JA4S is the server
hello counterpart. The repo implements the JA4 string assembly per the
2023 spec
([`internal/engine/botdef/ja4.go`](../../internal/engine/botdef/ja4.go)).
JA4 itself is BSD-3-Clause; the JA4+ family carries the FoxIO license.
The package implements the string assembly; it copies no FoxIO source.
JA4H stays unclaimed; the header-plane fingerprint is its in-repo
equivalent (Module 4, lesson 3).

Why fingerprints survive encryption: the hello flies before keys
exist. An observer needs no secret. A recorded hello reads the same
after the fact. That property makes the fingerprint a metadata surface:
it rides where the termination hop can compute it
([§12.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#121-detector-families)).

The transport codes: `t` marks TLS over TCP, `q` marks a QUIC Initial,
`d` marks DTLS. The golden-vector test derives the QUIC variant live.
ALPN rules part 1: the first offered value wins the code; values
outside UTF-8 take the hex fallback
([`ja4_test.go`](../../internal/engine/botdef/ja4_test.go)).

## Lesson 4 — the surfaces today: shipped pins and PENDING walls

| Surface | State | The pin |
|---|---|---|
| JA4 assembly + golden vectors | shipped | [`ja4.go`](../../internal/engine/botdef/ja4.go); `TestJA4GoldenVectors` |
| Header-plane fingerprint | shipped | [`headers.go`](../../internal/engine/botdef/headers.go) |
| Behavior windows + merge policy | shipped | [`behavior.go`](../../internal/engine/botdef/behavior.go), [`verdict.go`](../../internal/engine/botdef/verdict.go) |
| ClientHello extract into the ingest path | PENDING | no hop attaches a summary today |
| Kernel-side hello capture | PENDING | a named slice in the package doc |
| Known-tooling feed CR | PENDING | the digest-pinned feed of [§12.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#123-honest-limits) |

The extract wall is the load-bearing one. The S5 bot stage sees no
fragment until a hop attaches a summary. The slice boundaries live in
the package doc: no TLS parsing happens inside the botdef package.
Never a fabricated verdict: the detector stays silent without input.
The engine-TLS mode would compute the summary at the engine hop. v1
does not ship it (§6.3).

## Lesson 5 — QUIC: the UDP move, and the 0-RTT risk

QUIC carries the TLS 1.3 handshake and streams over UDP. Three facts
shape the product posture:

- The handshake rides QUIC Initial packets. The ClientHello stays
  readable without secrets. The summary transport code reads `q`.
- 0-RTT: a returning client sends early data with the first flight.
  The early flight replays: one recorded request re-fires byte for
  byte at the pool.
- The replay decision belongs to the termination hop. The gateway
  owns the 0-RTT knob; the WAF records no replay control today.

Product posture ([Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)):
HTTP/3 ingress is a tracked evaluation, not a v1 claim
([TR-29](https://github.com/trishula-dev/trishula/issues/29)). What
holds today: XDP sees UDP floods the same way as TCP floods
([§9.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory)).
What waits: QUIC packet framing needs userspace analysis. The flow
classifier walks TCP only at v0
([`bpf/flow_tc.c`](../../bpf/flow_tc.c)).

## Lesson 6 — rule anatomy: the fields each surface reads

| Rule | Expression | Wire anatomy | State |
|---|---|---|---|
| the planned JA4 CEL field | `request.tls.ja4 == "t13d1516h2_..."` | the ClientHello bytes the summary mirrors | PENDING — the §11.3 view carries method, path, query, rate windows |
| the JA4 detector fragment (S5) | no CEL — a Go verdict with confidence plus evidence | the summary struct fields | shipped; the input waits on the extract |
| the ALPN-driven h2 classification | no rule — parser classification | the ALPN offer, and the reconstructed h2 head (Module 1, lesson 4) | shipped at the engine hop |

The §11.3 view wall carries live evidence. The DX1 broken-policy
fixture asks for a body field, and the compile gate rejects it with
`no such key: body`
([`dx1-broken-pack.yaml`](../../lab/dx1/manifests/dx1-broken-pack.yaml)).
A `request.tls` scope rides the same wall: the view grows field by
field, and each field rides its own slice.

## Lesson 7 — the lab

Run the lab from a repo checkout:

```bash
bash lab/module-2/run.sh
```

| Leg | Surface | The gate |
|---|---|---|
| ja4 | `go test ./internal/engine/botdef/` over the JA4 tests — golden vectors, hash variants, ALPN codes, self-consistency | every golden vector reproduces; the QUIC transport variant derives |
| header-plane | the same package over the header-fingerprint tests | browser and tool shapes classify apart |
| h2-classification | `go test ./internal/engine/http2/` | gRPC and SSE heads reconstruct on the one request view |
| termination (opt-in) | `KIND_LAB=1`: the DX1 lab hop evidence, plus the Gateway listener read | the hop header shows the engine hop; the leg prints the live listener protocol |

The termination leg needs the DX1 lab up
([`lab/dx1/setup.sh`](../../lab/dx1/setup.sh)). The DX1 lab ships the
plain-HTTP listener today
([`dx1-gateway.yaml`](../../lab/dx1/manifests/dx1-gateway.yaml)). The
leg reads what the lab carries and prints it. An HTTPS-listener leg is
PENDING work on the lab. The full shape:
[`lab/module-2/README.md`](../../lab/module-2/README.md).

## Course links

| Where | Link |
|---|---|
| The academy index | [`docs/academy/README.md`](README.md) |
| The DX1 lab | [`lab/dx1/README.md`](../../lab/dx1/README.md) |
| This module's lab | [`lab/module-2/README.md`](../../lab/module-2/README.md) |
| The bot-detector families | [`internal/engine/botdef/`](../../internal/engine/botdef/) |
| The bot-defense spec | [spec §12](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#12-bot-defense--anti-automation) |
| The remaining map entries | [spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches) |
