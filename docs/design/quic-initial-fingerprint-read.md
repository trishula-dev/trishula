# QUIC initial-packet fingerprint read — the designed probe (TR-203 L5)

> **Trishula probe-design record TR-203 L5** — the design for the live read of
> the QUIC Initial packet's ClientHello shadow. Parent aggregate:
> [TR-203 #264](https://github.com/trishula-dev/trishula/issues/264), leaf L5.
> Posture record: [the h3 ingress posture](h3-ingress-posture.md); that record's
> probe [P2b](h3-ingress-posture.md#4-what-the-tracked-evaluation-must-probe--the-probe-map)
> defines the live read and files it PENDING. This note designs the read. It
> follows that record's register and the verdict-record method of
> [TR-44](protocol-conformance-verdict.md).
>
> **Spec refs:**
> - [§9.1 the two-plane principle](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle) ·
>   [§9.2 hook inventory](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory) ·
>   [§9.7 visibility contracts per mode](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode)

Status: designed probe. This record files a design. It ships no code, no harness
and no capability claim. Probe P2b stays PENDING. The PENDING status moves only
by PR with a recorded run ([the posture record's rule](h3-ingress-posture.md)).

## 1. The question, restated once

The posture record's probe map files P2b as PENDING. This note designs the read
and states everything the read needs. It answers 3 questions:

1. What does a QUIC Initial packet expose at the wire, before any key work?
2. What does the read recover behind the RFC 9001 key derivation, at which
   altitude?
3. Where does the kernel stay, and what does it read instead?

Decision rule for the record: the design makes no claim. The boundary sits
between the header plane and the payload plane. The kernel stays left of the
boundary.

## 2. The wire facts

The design rests on facts from the standards and from the repo, not on
assumptions.

| # | Fact | Source |
| --- | --- | --- |
| F1 | The Initial packet is a long-header packet. The header carries the form bits, the 4-byte version, the Destination Connection ID (DCID) and the packet number, all in cleartext form. | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), section 17.2 |
| F2 | The Initial keys derive from public values only. HKDF-Extract runs with the 20-byte version salt (0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a for QUIC v1) over the DCID. Two HKDF-Expand-Label secrets follow ("client in", "server in"), hashed with SHA-256. | [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), section 5.2 |
| F3 | Initial packets always use AEAD_AES_128_GCM, with keys from F2's chain, whatever cipher suite the later handshake negotiates. Header protection uses the AES-based scheme. The RFC states: "it is trivial to determine the keys used for Initial packets". | RFC 9001, section 5.3 and section 7 |
| F4 | "Initial packets are not protected with a secret key." Any party that records the datagrams can decrypt them. The ClientHello in an Initial gives no secrecy to its sender. | RFC 9001, section 7 |
| F5 | QUIC mandates ALPN. The decrypted ClientHello carries a real protocol offer, so the JA4 a-section's ALPN glyph derives from the shadow. | RFC 9001, section 8.1 |
| F6 | The PQ offer inflates the shadow. The X25519MLKEM768 offer carries a 1,216-byte client share (1,184 bytes ML-KEM + 32 bytes X25519) against 32 bytes for bare X25519 (group 4588 (0x11EC)). | [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024), section 4.1 and section 7.1; the go-client-x25519mlkem768 corpus row |
| F7 | The hybrid share adds 1,184 bytes over the bare X25519 offer. ClientHellos past the 1,200-byte minimum datagram span more Initial datagrams. The datagram count and the sizes stay visible at L3/L4. | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), section 14.1; the field measurement in the spec's [327] row |
| F8 | The JA4 grammar carries the QUIC transport glyph. A summary with transport 'q' renders the QUIC a-section. Probe P2a runs live over a summary struct. No packet reader exists in the tree. | internal/engine/botdef/ja4.go; the posture record's [P2a row](h3-ingress-posture.md#4-what-the-tracked-evaluation-must-probe--the-probe-map) |

## 3. The boundary — before and behind the salt

The read splits at the F2 key derivation. The split decides every reader's
altitude.

| Plane | Content | Reader |
| --- | --- | --- |
| before the derivation | the UDP/IP 5-tuple, the form bits, the version, the DCID, the datagram count and the datagram sizes | any L3/L4 reader: the XDP/TC classes |
| behind the derivation | the AEAD-decrypted crypto frames, the reassembled TLS ClientHello bytes, then the ClientHelloSummary fields: SNI, ALPN, ciphers, extensions, signature algorithms, the KEX offer | a userspace reader only |

The kernel leg reads the left column and nothing else. The posture record's
facts F1, F3 and F4 set the same line. The kernel counts and drops. It parses
no QUIC wire grammar.

## 4. What eBPF can and cannot read

**An eBPF reader (XDP/TC) can read:** the left column of section 3. The parse starts at the UDP payload's first byte. It reads the form bits and the version word. It takes the DCID bytes. The flow rows carry the sizes and the counts. This stays inside the L3/L4 altitude the posture record pins (the [hook inventory](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory)).

**An eBPF reader cannot read:** the payload plane. The reasons:

1. The derivation chain needs SHA-256 HKDF, AES-128-ECB masking and AEAD_AES_128_GCM per packet. The [hook inventory](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory) carries no such crypto path.
2. The [two-plane principle](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle) pins the kernel decision-free. The posture record's non-claim N2 forbids kernel QUIC parsing. The read preserves that non-claim.
3. The payload plane belongs to Model B in the [visibility contracts](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode): metadata-only signals without key custody. The Initial keys exist "in the air". The kernel still owns no user of them.

The kernel therefore counts and drops. The count classes sit in the UDP flow
rows of the TR-203 L1 slice, inside the [hook inventory](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory). The design asks the
kernel for nothing else.

## 5. The read design

| Item | Statement |
| --- | --- |
| Input | the ordered Initial datagrams of one QUIC connection, from a UDP capture feed |
| Feed owner | the §12 capture slice; the posture row names it the absent piece |
| Output | the ClientHelloSummary with transport 'q', the JA4 token, the pqc KEX record |
| Verdict path | detector evidence only; it feeds the merge policy of [§12.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#122-verdict-integration), never an identity claim |

The read runs userspace, at the termination leg. The steps:

1. Parse each datagram's long header: form bits, version, DCID.
2. Derive the Initial secrets per RFC 9001, section 5.2. The version map
   carries the v1 salt. QUIC v2's salt sits in [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369). An unsupported
   version gives a recorded miss, never a token.
3. Unmask the packet number per RFC 9001, sections 5.4.2 and 5.4.3. The
   sample offset sits 4 bytes past the packet-number field. The mask XOR
   covers the first byte and the packet number.
4. Decrypt the payload with AEAD_AES_128_GCM under the F3 keys.
5. Walk the CRYPTO frames and reassemble stream 0 in order.
6. Parse the ClientHello bytes into the ClientHelloSummary fields, with
   transport 'q'.
7. Run the grammar over the summary. The result = the JA4 token for the QUIC
   hop plus the pqc KEX record. The shape matches the corpus rows
   (internal/engine/botdef/testdata/ja4_vectors.json).

The design files the miss classes upfront. A server Retry re-keys the DCID;
the derivation restarts from the Retry's DCID per RFC 9001, section 5.2.
Datagram loss leaves stream-0 gaps. A coalesced datagram carries a tail with
no Initial. Each miss reports as a miss. The read never invents a token from
a partial stream.

## 6. The designed P2b row

The posture record's section 4 carries the row. This note carries the design
state of the same row:

| Probe | What it measures | Harness | Status |
| --- | --- | --- | --- |
| P2b | the decoded ClientHello shadow: the summary fields, the JA4 token and the KEX record off live Initial datagrams | none — needs the UDP capture feed | PENDING — no UDP capture feed; the §12 capture slice owns it |

The status stays PENDING. A recorded run on a feed flips it, by PR, with the
run receipt. The earlier row statement in the posture record stays as filed.

## 7. The non-claims of this record

| # | Non-claim | Anchors |
| --- | --- | --- |
| NC1 | The record ships no code, no harness and no run. Probe P2b stays PENDING. | Status; [§12.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#122-verdict-integration) |
| NC2 | The kernel gets no new hook, no crypto and no QUIC grammar. The §9.1 altitude holds. | [§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle); [§9.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory) |
| NC3 | The shadow adds no ban identity. The fingerprint group is client-stated and spoofable. | [§12.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#123-honest-limits); the spec's [329] row; [§13.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified) |
| NC4 | The read adds no PQ data-plane or PQ signature claim. | [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes) |
| NC5 | The cipher/KEX shift finding stays corpus-pinned, not spec-rewritten: the same stack's KEX flip leaves the JA4 token unchanged; the group list and the share size shift instead. | the go-client pair rows |

## 8. Record family

| Record | What it contributes here |
| --- | --- |
| [TR-203 #264](https://github.com/trishula-dev/trishula/issues/264) | the leaf's mandate; decision 4 and decision 5 |
| [The h3 ingress posture](h3-ingress-posture.md) | the probe map; the P2b row; the facts F1, F3, F4; the non-Claim N6 |
| [TR-44](protocol-conformance-verdict.md) | the verdict-record method; the h3 non-claim |
| [The TLS posture record](tls-posture-verdict.md) | the terminated-hop view the read serves |
| internal/engine/botdef/ja4.go | the grammar: the 'q' transport and the ja4f render |
| internal/engine/botdef/testdata/ja4_vectors.json | the PQC rows: the pinned tokens and the pqc KEX records |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) sections 5.2-5.4 and 7 | the derivation chain and the decryptability statement |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) section 14.1 | the 1,200-byte datagram rule |
| [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024) sections 4.1 and 7.1 | the hybrid group, the code point and the share size |
| [Academy module 5](../../docs/academy/module-5.md), lesson 2 | the share-size lesson the design cites |

## 9. Closure record

- The design files the read's 7 steps and the miss classes.
- The boundary = header plane (cleartext, kernel-legible) vs payload plane
  (userspace read, behind the RFC 9001 derivation).
- The kernel counts and drops; the design adds nothing to it.
- P2b stays PENDING. The row moves by PR with a recorded run.
- The corpus carries the KEX part of the offer; the grammar pins the same
  token across a KEX flip.
