# Academy Module 1 — the wire: HTTP/1.1, HTTP/2, and request smuggling

Module 1 of the teach-the-web curriculum. The curriculum map entry
lives in
[spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches).
The pedagogy rules live in
[spec §7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules).
The deliverable set lives in
[spec §7.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#73-deliverables).

Spec §7.2 fixes one pedagogy rule for this page: every rule example
cites its wire anatomy. Wire anatomy is the record of the request bytes
one rule reads. Lesson 6 carries that record for each example.

## The lessons

| # | Topic | The bytes on the wire |
|---|---|---|
| 1 | Framing | the request line, the header block, the body |
| 2 | Body length | Content-Length, chunked encoding, keep-alive framing |
| 3 | Strict parsing | bounded reads, named errors, no repair |
| 4 | HTTP/2 | frames, stream ids, HPACK, multiplexing |
| 5 | Smuggling | the CL/TE conflict, one request read as two |
| 6 | Rule anatomy | view fields mapped to wire bytes |
| 7 | The lab | the §11.8 corpus replay with verdict evidence |

## Lesson 1 — framing: the request line, the header block, the body

An HTTP/1.1 request is three parts.

```text
POST /v1/chat?q=hi HTTP/1.1\r\n          <- 1  the request line
Host: api.example.com\r\n                <- 2  the header block
Content-Type: application/json\r\n
Content-Length: 10\r\n
\r\n
{"q":"hi"}                               <- 3  the body (10 bytes)
```

The request line carries three tokens: the method, the target, the
version. The header block carries one field per line. One empty line
ends the header block. The body follows the empty line. The body
carries no end marker of its own.

## Lesson 2 — body length: Content-Length, chunked encoding, keep-alive

Keep-alive holds one TCP connection open across many requests. The
framing rule is the separator: it ends one message and starts the
next. A body takes its length from exactly one rule:

- `Content-Length: 10` — 10 body bytes follow the empty line.
- `Transfer-Encoding: chunked` — each chunk carries its size in hex;
  a chunk of size 0 ends the body.

RFC 9112 gives the transfer coding precedence when both fields appear
in one header block. A reader that takes Content-Length instead reads
a different body length. The engine does not guess: the parser takes
one framing answer before the next request can start.

## Lesson 3 — why the parser is strict

The HTTP/1 parser is
[`internal/engine/http1/http1.go`](../../internal/engine/http1/http1.go)
(TR-05b). The parser reads the request head only. No body bytes pass
through this slice; the body slice comes later (TR-05b names the
boundary).

The parser carries hard budgets:

- one line (the request line or one header line): 8 KiB
- the header block: 100 lines, 16 KiB total

Every malformed-input case is a named error. The names live in
`http1.go`:

- `ErrNoCRLF` — the request line lacks the CRLF terminator.
- `ErrNULInLine` — a NUL byte rides the request line.
- `ErrHeaderFold` — deprecated header folding appears.
- `ErrBadMethod`, `ErrBadVersion`, `ErrBadHeader` — malformed tokens.
- `ErrLineTooLong`, `ErrTooManyHeaders`, `ErrHeaderTooBig` — budget
  breaches.

The parser never repairs input. Repaired input can hide a framing
conflict; named errors stop that path.

## Lesson 4 — HTTP/2: streams, HPACK, multiplexing

HTTP/2 replaces the text framing with binary frames.

- One connection carries many streams. One stream carries one request
  and its response.
- Every frame carries a stream id. The stream id routes the frame.
- Multiplexing: frames of many streams share the one connection.
- HPACK compresses header blocks. HPACK keeps a table of fields seen
  before; a repeat field compresses to an index entry.

The h2 parser is
[`internal/engine/http2/http2.go`](../../internal/engine/http2/http2.go)
(TR-15):

- The parser reads HEADERS and CONTINUATION frames only. Other frames
  pass through with bounded accounting; none of them feed the view.
- A stream head releases the moment its header block reconstructs. An
  open stream never blocks the other heads.
- gRPC heads classify on content-type plus the `:path` full method;
  SSE heads classify on `text/event-stream`. The classification rides
  the same [§11.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#113-cel-as-the-developer-facing-dsl)
  request view.

h2 framing is unambiguous inside one stream: DATA frames run to
END_STREAM. The CL/TE ambiguity returns at a downgrade point: a hop
that converts h2 requests to HTTP/1.1 writes Content-Length framing it
computed. Lesson 5 covers why that matters.

## Lesson 5 — request smuggling: the CL/TE conflict

Request smuggling: one request reads as two at the next hop. `CL` is
Content-Length. `TE` is Transfer-Encoding. The anatomy:

```text
POST /v1/x HTTP/1.1\r\n
Host: api.example.com\r\n
Content-Length: N\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n\r\n
<the smuggled request bytes>
```

- Reader A takes Content-Length. Reader A cuts the body after N bytes.
- Reader B takes Transfer-Encoding. Reader B cuts the body at the
  chunk of size 0.
- The two cuts land at different bytes. The cut difference hides one
  full request inside another. One hop reads one request. The next hop
  reads two. The hidden request skips the checks the first hop ran.

The defenses live at parse altitude:

- One framing answer per message. RFC 9112 puts the transfer coding
  first when both fields appear.
- Conflicting or duplicated framing fields are a named error, never a
  repair path (lesson 3).
- Bounded reads stop the oversized-header shapes that frame the
  hidden request (lesson 3).

The spec carries the detection surfaces. The
[§11.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#113-cel-as-the-developer-facing-dsl)
request view names the `tx.flags.smuggling_suspect` flag. The
[§9.6](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest)
kernel fast path checks for duplicate Content-Length headers inside
its bounded window. The head parser keeps its slice boundary today:
framing verdicts on bodies are later slices, and the flags land with
the view slice that reads bodies.

## Lesson 6 — rule examples and their wire anatomy

The §7.2 rule in action. Each row names the bytes the rule reads.

| Rule | Expression | Wire anatomy |
|---|---|---|
| `DX-LAB-001` — the enforced DX1 lab rule ([`lab/dx1/manifests/dx1-rulepack-sqli.yaml`](../../lab/dx1/manifests/dx1-rulepack-sqli.yaml)) | `request.method == "POST" && path.matches("/v1/chat/*") && request.query.contains("UNION")` | the request line: the method token, the target, and the query part of the target (the bytes after `?`) |
| `TR02-001` — the shipped seed rule ([`rules/cel/seed.yaml`](../../rules/cel/seed.yaml), action `log`) | `request.method == "POST" && path.matches("/v1/chat/*") && request.rate_windows["5m"].requests > 40` | the request line again, plus the per-source request counters behind `request.rate_windows` ([§9.5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#95-kernel-side-rate-accounting-feed-13)) |
| the §11.3 spec example | `request.body.?json.messages.size() > 128` | the message body; the lesson-2 framing rule decides where that body ends |

Three surfaces run these rules today:

- `go run ./cmd/trishula --selftest` prints the seed-rule verdicts on
  the sample request fixture. `request.method` reads the request
  line; `path.matches` reads the target.
- `cmd/attackdemo cel <method> <path> <rate>` feeds the same seed
  rule one rate number and prints the verdict.
- The DX1 lab enforces `DX-LAB-001` on a live kind cluster: the
  blocked request returns 403 with `X-Trishula-Rule: DX-LAB-001`
  (see [`lab/dx1/README.md`](../../lab/dx1/README.md)).

## Lesson 7 — the lab: replay the §11.8 differential corpus

Spec §7.2 pins Module 1's teaching corpus to the §11.8 differential
corpus. The corpus lives in
[`test/crs-differential/corpus/`](../../test/crs-differential/corpus/):
20 recorded requests in go-ftw shape, each with an expected rule-id
set. The [
§11.8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate)
gate scores verdict-level parity on the same corpus: block/log/pass,
matched rule ids, and the score ladder.

Run the lab from a repo checkout:

```bash
bash lab/module-1/run.sh
```

The lab converts every corpus case to a raw HTTP/1.1 wire file and
replays each file through the embedded-Coraza surface
(`cmd/attackdemo crs`; the demo CRS slice). It then runs the parity
gate itself, which scores the corpus against the full CRS slice: the
expected rule-id sets, verdict-level
([§11.8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate)
parity). The run transcript carries one verdict surface per case and
the parity line. The full shape:
[`lab/module-1/README.md`](../../lab/module-1/README.md).

The corpus is shared: `test/crs-differential/` embeds the same files
for the CI parity gate ([§7.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#73-deliverables)
names the adversarial corpora as shared teaching sets).

## The product is the textbook

Spec §7.2 names the product's teaching mechanism: the verdict trace
carries the module link, so a developer reads the lesson at incident
time (the DX5 deliverable in
[§7.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#73-deliverables)).
The verdict vocabulary lives in
[`internal/engine/ladder/ladder.go`](../../internal/engine/ladder/ladder.go).
The generator that ties a verdict to its module is a spec
deliverable, not a shipped surface; this row records the boundary.

## Course links

| Where | Link |
|---|---|
| The academy index | [`docs/academy/README.md`](README.md) |
| The DX1 lab | [`lab/dx1/README.md`](../../lab/dx1/README.md) |
| This module's lab | [`lab/module-1/README.md`](../../lab/module-1/README.md) |
| The differential harness | [`test/crs-differential/README.md`](../../test/crs-differential/README.md) |
| The remaining map entries | [spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches) |
