# Socket-plane fast path — mechanism design (TR-39a)

> **Trishula design note TR-39a** — part 1 of 3 of the socket-plane note. Parent record:
> [TR-39 #51](https://github.com/trishula-dev/trishula/issues/51). Ladder and census records
> own parts 2 (fail-open ladder) and 3 (census); the assembled note with the perf protocol is
> `docs/design/socket-plane-fast-path.md`.
>
> **Spec refs:** [§9.9 socket-plane fast path](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment) ·
> [§9.7 visibility contracts](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode) ·
> [§9.3 maps](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state)

Status: design study. This note records mechanism decisions. It ships no code and makes no
capability claim. The source study is Beeline — "Enforcing Application-Layer Policies in eBPF"
(arXiv:2605.31084; Brandner, Mishra, Miano, Panda, Antichi, Vanbever). The socket plane is tier
one of enforcement, not the enforcement; the fail-open ladder carries that contract, not this note.

## 1. Scope

The socket plane sits one altitude above the XDP shield. The TCP stack reassembles packets there.
`strparser` delineates TLS records and application messages there. The plane observes plaintext,
message-shaped traffic on legs where Trishula owns TLS termination (Model A, §9.7). The plane
enforces header-class policies from the compiled bundle (§8.1). It never inspects a request body.

The design follows the parse–match–action synthesis of the source study. The control plane
synthesizes per-policy programs from the `WAFPolicy` subset. The kernel runs the programs at the
`SK_SKB` (ingress, egress) and `SK_MSG` (local) hooks. Verdict authority stays userspace (§9.3,
§20.3.3): the kernel enforces recorded dispositions and compiled policy matches.

## 2. Parse stage

Rule: the synthesis step builds the parse DFA at control-plane start, from the policy set.

The parse stage extracts policy-relevant information from each message. It uses a deterministic
finite automaton (DFA) per protocol: HTTP/1.1 and HTTP/2 define one DFA each in the tracked
evaluation. The control plane synthesizes the DFA from the policy-relevant header set at start:
the fields the active policies read. Irrelevant byte ranges carry no extraction work; the DFA
skips them. The DFA encodes as an integer matrix, as in the source study. The matrix loads into
the data plane at program attach. The executable that steps the matrix stays fixed across policies.

The stage integrates with `strparser`. A partial message stops extraction; `strparser` waits for
more bytes. A complete message yields the header vector `H`: fixed slots that store located ranges
(method, path, authority, the policy-relevant header set plus lengths). The source study stores
pointers plus range metadata in `H`; this design keeps that shape. The kernel never copies a body
byte. `H` carries header-class data only.

Decision: **adopt** the parse mechanism of the source study. Delta: the DFA set synthesizes from
the `WAFPolicy` subset header set, not from observed proxy configurations; the header-set input
comes from the bundle compile (§8.1), so recompiles rebuild the DFAs.

## 3. Match stage

Rule: the match stage runs compiled `if` chains over `H`; chain order encodes policy priority.

The match stage selects the policy for each message. The stage compares the fields of `H` against
the match criteria of the compiled policies. The comparison list runs as compiled `if` chains. The
control plane orders the chains from the compile: `WAFPolicy` rule priority and endpoint scope set
the order. The stage selects between a policy action sequence and a slow-path route. It stops the
decision-free principle of §9.1 no more than the XDP ACL does: the policy compiles from CRDs at
userspace; the kernel enforces the compiled artifact.

The source study matches with basic string comparison and names no regex support at v1. This
design keeps that bound. Value predicates beyond equality (substring, glob) need a bounded-scan
primitive; the census record (part 3) carries that decision for the CEL vocabulary.

Decision: **adapt**. The if-chain form is adopted; the priority order derives from the bundle
compile order (rule priority, endpoint scope), not from an endpoint table of the source study.

## 4. Action stage

Rule: action sequences use the restricted primitive library only. Every sequence terminates in
`drop` or `forward`.

| Primitive | Meaning | Beeline name |
| --- | --- | --- |
| `compare` | Compare two extracted or constant values | compare |
| `read`/`write` | Read or write a bounded range of the message | read/write |
| `encode`/`decode` | Apply or remove a named scheme (base64url and kin) | en-/decode |
| `hash` | Apply a named hash scheme | hash |
| `get`/`set` | Read or write shared-map state | get/set |
| `forward` | Send the message to a target socket | forward |
| `drop` | Drop the message | drop |

Each action is one small function. Sequences assemble from templates: a template carries the
control flow plus placeholders; synthesis fills placeholders from the compiled policy parameters.
Every template in the source study stays under 70 lines of C. This design keeps the same size
envelope as the synthesizable-unit budget (section 8).

Two classes stay gated. The `encode`/`decode` class needs a kernel access path. The `hash` class
needs the same; the eBPF runtime on current kernels lacks hash and encode helpers (section 9). A
class that needs a gated primitive routes to the slow path until the gate opens. The synthesis
step never inlines a gated primitive.

Decision: **adopt** the primitive library and the termination rule. Delta: no `en-/decrypt`
template at the tracked evaluation; decryption lives in the kTLS handoff (section 7), not in a
policy action. The `hash` template exists but stays gate-locked (JWT HS256, ring-hashing balance).

## 5. XDP↔socket shared-map schema

Rule: the socket plane reads the §9.3 maps. It writes nothing to them.

| Map (§9.3) | Producer → consumer | Socket-plane role |
| --- | --- | --- |
| `verdict_cache` | engine → shield | read: cached allow/block disposition per flow key |
| `ban_table` | ban engine → shield | read: ban hit carries expiry + reason code |
| `src_rep` | engine → shield | read: reputation score for the source key |
| `rate_windows` | shield counters | read: request-rate EWMA per source for CEL rate predicates |

The two planes share one verdict authority. The engine decides; the XDP shield and the socket
plane enforce. A ban issued by the engine is visible at both altitudes: the XDP ban-table hit
drops pre-TCP; the socket-plane ban hit drops the message. A socket-plane enforcement hit is not
a new decision; it is a read of engine state. The wire layout of the shared keys follows the
house convention: 200-byte aligned structs, network-order `be16` ports, BTF-verified Go mirrors.
The XDP contract (TR-03) owns those layouts; this design reuses them and adds no map family.

Decision: **adapt**. The source study keeps get/set state in its own maps. This design binds get
and set to the existing §9.3 maps, so the two planes enforce one verdict authority (TR-03). New
map families need their own record.

## 6. Control plane: connection-pool ownership

Rule: eBPF cannot dial. The control plane owns every socket in the pool.

The pool holds open connections keyed by target. A `forward` action queries the pool. A miss
forwards the message to the control plane, which dials the target, publishes the socket, and
sends the message. The pool fills lazily at runtime and stays warm while peers keep the sockets
open. The control plane tracks sockets of protected processes through the `SOCK_OPS` hook, as in
the source study; the hook reports socket creation and teardown across the namespace. Per-flow
response routing state lets the plane hand answers back to the right connection.

The source study runs this control plane as a 4K-line Rust agent. This design places the control
plane in the Go shield (TR-03 estate): the shield already owns map publish and reconcile loops.
The pool map is an eBPF hash map; the control plane is its only writer.

Decision: **adopt** the lazy-fill pool and the `SOCK_OPS` tracking. Delta: the control plane lives
in the Go shield, not in a separate Rust runtime.

## 7. kTLS and strparser constraints

Rule: Model A only. The plane reads plaintext on legs where Trishula owns termination.

The control plane performs the handshake and holds the session keys. It hands the crypto state to
the kernel (`TLS_TX`/`TLS_RX` ULP). `strparser` then delineates records, decrypts, and hands
plaintext messages to the plane. The price is kernel-resident session keys; the §9.7 record owns
the threat model, blast radius and rotation obligations.

Where termination is external to Trishula (the default gateway leg), the plane sees ciphertext
and metadata only (Model B). Header and body policies stay unavailable there; enforcement covers
connection- and fingerprint-level verdicts. The plane never extracts keys from application memory.

Decision: **adopt** with scope. The mechanism applies on the secondary mode and pod-mTLS legs
(§9.7 Model A). The gateway leg keeps Model B semantics.

## 8. Verifier envelope for synthesized programs

Rule: one synthesized program, one size envelope, asserted before attach.

The verifier checks every program at load. The synthesis step keeps programs inside the envelope:

- each template stays under 70 lines of C (source-study bound);
- one assembled program targets a single loadable unit; the tracked evaluation uses no tail calls;
- loops carry compile-time bounds or stay out (the verifier rejects unbounded loops);
- the instruction budget per program is a compile-time constant, asserted in CI at load time.

The compile-probe discipline of the engine bundle carries over: a program that fails to load
fails the apply, never a request mid-flight. The load gate records the disposition per policy
class; the fail-open ladder (part 2) maps that disposition to a tier. bpf2go builds CO-RE objects
for both architectures, as the shield build does today.

Decision: **adopt** the template-envelope posture. The source study proves each template against
the verifier once; this design repeats the proof per synthesis in CI, per bundle.

## 9. Kernel-module dependency assessment

Rule: the design does not adopt a kernel module at the tracked evaluation.

The source study ships a 172-line out-of-tree module. It exposes hash and encode helpers the
eBPF runtime lacks. Kernels 6.10+ expose kfuncs for en-/decryption; hash and encode coverage is
separate and incomplete. The options:

| Option | Cost | Decision |
| --- | --- | --- |
| Skip the gated classes (JWT HS256 verification, ring-hashing balance) | those classes enforce at the slow path | **adopt** |
| Adopt a thin out-of-tree module | supply chain: module build per kernel version, signing, verifier-CI drift, security review | **reject** at this stage |
| Wait for upstream kfunc coverage | re-open the census (part 3) when coverage lands | **recorded trigger** |

The census record (part 3) sizes the blocked classes: JWT HS256 sits inside the §9.9 subset and
stays slow-path-bound until hash coverage exists. The TR-40 compiler spike inherits this gate and
re-reads it when the target kernel moves.

Decision: **reject** the kernel module for the tracked evaluation. Re-evaluation triggers on
6.10+ kfunc coverage for hash/encode, not on demand.

## 10. Decision record — mechanism components

| Component | Source-study mechanism | Decision | Delta |
| --- | --- | --- | --- |
| Parse stage | Policy-specific DFAs, integer-matrix encoding, strparser wait | adopt | DFA input = bundle header set |
| Header vector `H` | Fixed slots, pointer + range metadata | adopt | Body bytes never enter `H` |
| Match stage | Compiled `if` chains over `H` | adapt | Order = bundle rule priority |
| Action library | 8 restricted primitives, drop/forward termination | adopt | No en-/decrypt template; hash gate-locked |
| Shared state | get/set over own maps | adapt | get/set binds to the §9.3 maps (TR-03) |
| Connection pool | Lazy fill, `SOCK_OPS` tracking | adopt | Control plane in the Go shield |
| kTLS handoff | Control plane owns handshake + keys | adopt | Model A legs only (§9.7) |
| Verifier envelope | Template-proven synthesis | adapt | Per-bundle CI load proof |
| Kernel module | 172-line out-of-tree hash/encode module | reject | Skip gated classes; upstream trigger recorded |

Each decision feeds the borrow-vs-build question, spec
[§20.3 Q7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions)
(TR-36). The assembled note consolidates the record and adds the perf protocol.
