# TLS termination key exchange — the PQC termination posture (TR-203 L4)

> **Trishula posture record TR-203 L4** — the post-quantum termination
> statement. Parent decision: [TR-203 #264, decision
> 4](https://github.com/trishula-dev/trishula/issues/264). Termination
> altitude sources: the [H3 ingress posture
> record](../design/h3-ingress-posture.md) facts F1/F2 and the [TR-34 TLS
> mode](https://github.com/trishula-dev/trishula/issues/34) (the engine's
> secondary mode, `cmd/engine/tls.go`).
>
> **Spec refs:** [§10.2 the contract](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#102-the-contract-trishula-as-a-gateway-api-citizen) · [§6.3 non-goals (v1)](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#63-non-goals-v1)

> More: [§9.7 visibility contracts per mode](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode) · [§20.1 risk register](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#201-risk-register) · [§20.2 phasing](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#202-phasing) · [Appendix A: roadmap notes](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)

Status: the profile is live on the repo's engine listener. The lab terminator
speaks the hybrid on the 2.x dataplane. The gateway-side knobs read as recorded
posture: this repo carries no verified run for them. The PQ signatures (the
CA/cert chain) stay on the 2026.02/03 calendar lanes.

## 1. The rule and the surfaces

Decision 4 of [TR-203 #264](https://github.com/trishula-dev/trishula/issues/264)
pins the rule: X25519MLKEM768 sits on every termination surface the repo
controls. The group = the IETF hybrid X25519 + ML-KEM key exchange (0x11EC).
The [H3 posture record](../design/h3-ingress-posture.md) facts F1/F2 hold:
transport termination sits at the gateway/ingress. The engine reads the
gateway's upstream legs only.

| Termination surface | Home | Key exchange | Recorded transcript |
| --- | --- | --- | --- |
| the engine listener | `cmd/engine` (the TR-34 `--tls-cert`/`--tls-key` gate) | pinned: X25519MLKEM768 + X25519 | the profile test, section 5.1 |
| the lab terminator | NGF in the DX1 lab (the `https` listener row, `cue/lab/dx1/gateway.cue`) | the dataplane image's TLS stack; 2.7.2 = OpenSSL 3.5.8 default (the hybrid on) | the termination read, section 5.2 |

Post-GA items stay out: re-encryption (the standing non-goal line, TR-203) and
the PQ signature migration. The key exchange never reads the certificate: the
negotiated group is independent of the cert algorithm.

## 2. The engine listener profile

The listener spec pins MinVersion TLS 1.2 plus the explicit key-exchange list:

- The list = `CurvePreferences` of `[X25519MLKEM768, X25519]`. Hybrid first.
  X25519 = the classical fallback. TLS 1.2 legs negotiate X25519: the hybrid
  rows are TLS 1.3 groups.
- The pin is a repo decision. The Go default carries the hybrid from Go 1.24.
  The pin keeps the set stable across Go release drift. The profile test holds
  the exact set (`TestTLSTerminationProfileSpeaksTheHybrid`).
- No ML-KEM implementation lands in the repo. `crypto/tls` carries the KEX.
  The repo never hand-rolls key agreement.
- Operator boundary (measured, go1.26.0): the process env
  `GODEBUG=tlsmlkem=0` strips the hybrid handshake even under the explicit
  pin. The env run negotiates X25519 and the hybrid rows fail. The profile
  never defeats that env.

## 3. The lab terminator — values, verified against the chart

The lab installs NGF from `oci://ghcr.io/nginx/charts/nginx-gateway-fabric`
(2.7.2 default; 1.6.2 = the single-pod fallback; `lab/dx1/setup.sh` carries
both lanes). Verification basis: the 2.7.2 chart package pulled from the same
OCI tag the lab installs. This lane's PR carries the store evidence.

Chart census (`values.yaml`, the 2.7.2 package):

- The listener TLS surface = the Gateway API row. An `HTTPS` listener with
  `tls.mode: Terminate` and a `certificateRefs` Secret. The chart's own
  provisioned-gateway example documents the same shape.
- The chart carries **no** listener cipher/group knob. No `ssl_protocols`
  value, no `ssl_ciphers` value, no `ssl_conf_command` value exists in its
  templates. The negotiated set therefore comes with the dataplane image's
  TLS stack.
- The 2.7.2 dataplane image (arm64, the same tag): `nginx 1.31.6` built with
  `OpenSSL 3.5.7`, running `3.5.8`. OpenSSL ≥ 3.5 carries the hybrid. The
  read below negotiates the hybrid with the image default.
- The 1.6.2 fallback dataplane (the live pod today): `nginx 1.27.4` built
  with `OpenSSL 3.3.2`. No ML-KEM: the read negotiates X25519 and files the
  classical finding. The fallback lane stays a classical lane.

The DX1 lab carries the listener in `cue/lab/dx1/gateway.cue`. The Secret
fixture step sits in `lab/dx1/setup.sh` (`dx1-lab-tls`; a self-signed lab
pair, never a product cert).

**Gateway-side operator posture (recorded, not run).** The chart sets no
group knob for the lab topology. An operator's own estate reaches the same
posture one of 2 ways. Way 1 = the TLS-stack default (an OpenSSL 3.5+
dataplane). Way 2 = NGINX-level `groups` configuration under NGF custom
config. This repo holds no verified run for those knobs. The knobs sit on
the operator's NGF deployment, not in a manifest this tree applies.

## 4. The cloud-LB cipher posture (recorded text)

The cloud-LB ciphers cite their surface and carry no verified run from this
repo. The estate's topology puts a managed LB in front of the ingress
([spec section 10.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#102-the-contract-trishula-as-a-gateway-api-citizen)).
The edge-leg group set comes from that LB's own policy class. Examples:
an NLB or ALB TLS listener policy, a GCP L7 LB cipher suite, a CDN TLS
profile. That leg terminates outside every surface this repo controls. Its
posture text reads:

- The edge LB listener negotiates the hybrid once its provider policy
  supports one. AWS: a TLS listener policy with a hybrid-capable security
  policy. GCP: a cipher profile with ML-KEM hybrids. Cloudflare edge: the
  automatic ML-KEM default. Provider knob names differ. The group is the
  same X25519MLKEM768.
- The repo files no claim on those knobs. No manifest of this tree reaches
  a cloud LB, so this record files no transcript for it. The operator's
  recorded run (its own provider, its own lane) owns that evidence.

## 5. The recorded transcripts

### 5.1 Engine listener surface

Run (the go.mod toolchain pinned):

```bash
GOTOOLCHAIN=go1.26.0 go test ./cmd/engine/ \
  -run 'TestTLSTerminationProfileSpeaksTheHybrid' -v
```

The negotiated line and the row verdicts:

```text
=== RUN   TestTLSTerminationProfileSpeaksTheHybrid/the-profile-pins-the-hybrid-offer-set
=== RUN   TestTLSTerminationProfileSpeaksTheHybrid/the-terminated-leg-negotiates-the-hybrid
    tls_test.go:144: negotiated key exchange: X25519MLKEM768
=== RUN   TestTLSTerminationProfileSpeaksTheHybrid/a-classical-client-falls-back-to-x25519
    tls_test.go:166: negotiated key exchange: X25519
=== RUN   TestTLSTerminationProfileSpeaksTheHybrid/a-pinned-client-negotiates-the-hybrid
    tls_test.go:192: negotiated key exchange: X25519MLKEM768
--- PASS: TestTLSTerminationProfileSpeaksTheHybrid (0.01s)
    --- PASS: TestTLSTerminationProfileSpeaksTheHybrid/the-profile-pins-the-hybrid-offer-set (0.00s)
    --- PASS: TestTLSTerminationProfileSpeaksTheHybrid/the-terminated-leg-negotiates-the-hybrid (0.00s)
    --- PASS: TestTLSTerminationProfileSpeaksTheHybrid/a-classical-client-falls-back-to-x25519 (0.00s)
    --- PASS: TestTLSTerminationProfileSpeaksTheHybrid/a-pinned-client-negotiates-the-hybrid (0.00s)
PASS
ok  github.com/trishula-dev/trishula/cmd/engine	0.480s
```

The watched RED run (pre-profile) carries its output in the RED commit. The
env-boundary run (`GODEBUG=tlsmlkem=0` on the same command) negotiates
X25519 and fails the 2 hybrid rows. The full transcripts sit in the lane's
PR evidence.

### 5.2 Lab terminator surface

Run (the DX1 lab up; kind or OrbStack-Docker provider; NGF 2.7.2):

```bash
bash lab/dx1/pqc-termination-read.sh
```

The read's transcript (the kind lab, this lane's PR):

```text
terminator: kubectl -n nginx-gateway — the lab gateway TLS leg
gateway conditions:
Accepted=True
Programmed=True
PASS  the dx1-lab-tls fixture Secret is in place
Service NodePorts:
  port-443 port=443 nodePort=31538
PASS  the https NodePort row is live
---- handshake transcript (openssl client: /opt/homebrew/opt/openssl@3.5/bin/openssl) ----
subject=CN=*.dx1.example.com
issuer=CN=*.dx1.example.com
Negotiated TLS1.3 group: X25519MLKEM768
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
--------------------------------------------------------
PASS  the lab terminator negotiates the X25519MLKEM768 hybrid (the recorded transcript above)
```

On a 1.x-arch lab the same read fails with the classical finding (the
OpenSSL 3.3.2 dataplane). The read never reports a classical group as a
pass.

## 6. The boundary — this record does NOT

1. Ship the PQ signature migration. The CA/cert chain = the 2026.02/03
   calendar lanes' work. The lab fixture Secret = the key-exchange leg's
   plumbing only.
2. Touch the re-encryption boundary. It stays the post-GA piece (the lane's
   ruling).
3. Add any data-plane claim past the key exchange. The engine's parse
   surface and verdict vocabulary ignore the negotiated group: the
   [H3 posture record](../design/h3-ingress-posture.md) non-claims hold.
4. Verify a cloud-LB knob. Section 4 files posture text only.
5. Change the JA4 corpus. The PQC JA4 vectors belong to the corpus leaf
   (TR-203 L5). The JA4 string shifts with the ClientHello's larger key
   share; that work stays out here.
