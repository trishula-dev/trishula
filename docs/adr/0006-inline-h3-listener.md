# 0006 — Serve the inline H3 listener on the repo-pinned x/net QUIC transport

Status: accepted

## Context

TR-203 leaf L3 (issue
[#264](https://github.com/trishula-dev/trishula/issues/264), leaf 3) grows the
TR-34 TLS secondary mode a QUIC/HTTP-3 listener. The listener carries three
surfaces. The `--h3-listen` flag opens the leg. The TCP TLS responses carry
the Alt-Svc advertisement. The engine's own h3 request view serves the
requests. The wire layer needs a QUIC transport plus an RFC 9114 message
layer.

The tree carries no QUIC stack today. Three options read out:

1. **The Go team's `golang.org/x/net/quic`** — the QUIC transport inside
   x/net v0.61.0. The repo's `go.mod` already pins that module as a direct
   dependency. The package is a work in progress under the Go project's
   banner. Its documented limitations include two named rows: 0-RTT carries
   no support, and address migration carries none. The module owns no RFC
   9114 layer. The frames, the SETTINGS and the QPACK subsets sit nowhere
   in it. The listener files its own minimal message layer in the repo.
2. **`github.com/quic-go/quic-go`** — the ecosystem's full HTTP/3 stack
   (MPL-2.0). Adopting it ships a new direct module dependency. The repo
   does not carry that module today. The dependency decision stays with the
   operator.
3. **An in-repo QUIC/TLS implementation** — banned. The repo vendors no new
   crypto surface.

## Decision

The listener serves on `golang.org/x/net/quic`. The repo's `go.mod` already
pins x/net v0.61.0. The transport sits inside the already-pinned module.
The import adds one new indirect row: `golang.org/x/crypto v0.58.0` (BSD-3,
the Go team's module). The repo files its own RFC 9114 layer
(`cmd/engine/h3.go`) and a QPACK subset (`cmd/engine/qpack.go`). The subset
reads the capacity-0 static/literal shape the listener announces. The
Huffman decoding comes from `golang.org/x/net/http2/hpack`; that package is
already a repo import surface. The listener vendors no crypto
implementation. The TLS shape = a stdlib `crypto/tls` config that carries the
unchanged TR-203 L4 key-exchange profile. The quic-go option stays open for
the operator: one direct dependency swap, at the operator's own decision.
The listener's surfaces (the gate, the advertisement, the handler path) keep
their shape under that swap. This record does not decide a quic-go
adoption.

## Consequences

The 0-RTT posture reads reject by construction. The transport's documented
limitation list carries "0-RTT is not supported". The listener's TLS shape
pins no session-resumption material (a nil session cache). Probe P5's dated
read lands in the
[posture record](../design/h3-ingress-posture.md).

The package is a work in progress. It sits outside the Go security policy.
The mode stays feature-gated and opt-in. The spec's
[non-goals boundary row](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#63-non-goals-the-standing-boundary)
carries the live shape.
A x/net release that changes the package's API costs one re-pin commit.

The kernel plane is untouched. The QUIC leg terminates in userspace. The
kernel's counter classes read the traffic as UDP
([the hook inventory](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory)).
