<div class="cover" markdown="1">

# Trishula

## Developer-First, eBPF-Native Web Application & API Security for Kubernetes

**Product Specification & Project Charter**

*Trishula: the trident — **kernel shield**, **userspace engine**, **control plane**.*

<div class="meta">Revision v4 · October 2026 · github.com/trishula-dev · trishula.dev</div>

</div>

<div class="pagebreak"></div>

## Table of Contents

0. [Front Page — What is Trishula?](#0-front-page--what-is-trishula)
1. [Executive Summary](#1-executive-summary)
2. [Positioning & Non-Negotiable Design Decisions](#2-positioning--non-negotiable-design-decisions)
3. [Problem Statement](#3-problem-statement)
4. [Related Work — What We Borrow, Where We Sit](#4-related-work--what-we-borrow-where-we-sit)
5. [Developer Experience Charter](#5-developer-experience-charter)
6. [Vision, Goals, Non-Goals](#6-vision-goals-non-goals)
7. [Teach-the-Web Curriculum](#7-teach-the-web-curriculum)
8. [Architecture](#8-architecture)
9. [eBPF Packet Path](#9-ebpf-packet-path)
10. [Gateway API Integration — NGF Reference Deployment](#10-gateway-api-integration--ngf-reference-deployment)
11. [Rule Engine & Detection](#11-rule-engine--detection)
12. [Bot Defense & Anti-Automation](#12-bot-defense--anti-automation)
13. [Rate Limiting, DoS Response & Temporary Bans](#13-rate-limiting-dos-response--temporary-bans)
14. [ML & Adaptive Detection](#14-ml--adaptive-detection)
15. [OpenTelemetry Observability](#15-opentelemetry-observability)
16. [Kubernetes Deployment Model & Operations](#16-kubernetes-deployment-model--operations)
17. [Performance Targets & Benchmark Plan](#17-performance-targets--benchmark-plan)
18. [Threat Model of Trishula Itself](#18-threat-model-of-trishula-itself)
19. [Reference Implementation](#19-reference-implementation)
20. [Risks, Mitigations & Phasing](#20-risks-mitigations--phasing)
21. [Success Metrics & Adoption Gates](#21-success-metrics--adoption-gates)
- [Appendix A: Roadmap Notes](#appendix-a-roadmap-notes)
- [Appendix B: Glossary](#appendix-b-glossary)
- [Appendix C: Sources](#appendix-c-sources)
- [Appendix D: Research Dossiers](#appendix-d-research-dossiers)
- [Appendix E: Similar Projects — and Why We Did Not Build On Them](#appendix-e-similar-projects--and-why-we-did-not-build-on-them)

<div class="pagebreak"></div>

## 0. Front Page — What is Trishula?

> **Trishula is an open-source, eBPF-accelerated web application and API security layer for Kubernetes.** Ordinary application developers — not WAF specialists — understand it, configure it and trust it. A per-node eBPF shield stops floods and repeat offenders in the kernel. A userspace engine carries deep HTTP inspection: positive security, bot detection and rate-based temporary bans. A Kubernetes operator turns policy into compiled, signed bundles. The design is **Kubernetes-native by construction**: policy is YAML in Git. Enforcement is Gateway API + eBPF. Every verdict is an OpenTelemetry record.

<div class="frontcard" markdown="1">

| | |
|---|---|
| **What it is** | eBPF data plane + userspace WAF/API-protection engine + Kubernetes operator, three deployables, one policy language |
| **What it runs on** | Standard Kubernetes (kind/minikube → k3s → managed), kernel ≥ 5.8; NGINX Gateway Fabric is the reference gateway — every traffic-path claim is demonstrated against it first |
| **What it enforces** | OWASP CRS signatures *and* positive security (OpenAPI), bot/anti-automation detection, per-route rate limiting, score-based **temporary bans** (fail2ban-for-HTTP, a specified algorithm) |
| **What developers write** | CEL expressions over a structured request view, OpenAPI specs, plain YAML CRDs — `kubectl apply` is the whole deployment story |
| **What it teaches** | HTTP/1.1, HTTP/2, HTTP/3, TLS, QUIC, post-quantum readiness — via the docs, labs, and a curriculum (§7), SPIFFE/SPIRE-style: the product is a teacher |
| **License** | MIT · full OSS dependency chain · no data-plane exit to third parties |

</div>

```mermaid
flowchart LR
    DEV["Developer<br/>writes YAML + CEL<br/>(no WAF dialects)"] --> GIT["Git / GitOps"]
    GIT --> OP["trishula-operator<br/>(CRDs → signed bundles)"]
    OP -->|"policy"| ENG["trishula-engine<br/>deep inspection:<br/>CRS + positive security<br/>+ bots + rate rules + ML"]
    OP -->|"maps + ban tables"| SH["trishula-shield<br/>eBPF @ XDP/TC<br/>floods, ACLs, bans"]
    GW["NGINX Gateway Fabric<br/>(reference gateway)<br/>TLS + Gateway API"] -->|"steers HTTPRoutes<br/>as a plain backend"| ENG
    SH <--->|"kernel events<br/>(ring buffer)"| ENG
    ENG --> POOL["Inference / app<br/>pods"]
    ENG -->|"OTLP logs+metrics+traces"| OBS["OTel Collector →<br/>your backend"]
```

*Figure 0. The developer's view: everything is YAML. The operator compiles it. The shield and engine enforce it. NGF fronts it. OpenTelemetry records it.*

**The thesis in one line:** security wins when developers adopt it. mTLS, OAuth/OIDC, vaults and ACLs reached ubiquity through developer-friendly tooling. **The WAF is the last major security control without developer adoption.** Trishula's purpose brings it into developer practice.

<div class="pagebreak"></div>

## 1. Executive Summary

**The one-liner.** Trishula is an open-source, eBPF-accelerated web application firewall and API-protection system for Kubernetes. The product pairs a per-node eBPF shield with a userspace deep-inspection engine. CRDs govern both. The engine sits *inline* between a Gateway-API data plane and the application/model pools behind it. **NGINX Gateway Fabric (NGF) is the reference deployment** — open source end to end (Apache-2.0, NGINX core). Every integration claim is validated against NGF before any other gateway carries a claim.

**Why now.** Kubernetes-native HTTP ingress has consolidated around Gateway API. AI-inference traffic is its dominant workload: long bodies, streaming responses (SSE), token-metered endpoints and multi-tenant model pools. The request shapes are adversarial surface. Prompt injection, jailbreaks, training-data exfiltration, credential stuffing and classic OWASP injection arrive on the same wire. The incumbent answers are either an out-of-band proxy hop with its own config language, or nothing. Neither option matches developer practice.

**What it is.** Three independently deployable planes:

- **eBPF data plane (`trishula-shield`, DaemonSet).** XDP sits at the NIC: L3/L4 ACLs, SYN/UDP flood tarpits, verdict-cache and **ban-table** enforcement. TC runs on node/pod veths: flow classification, plaintext fast-path probes, ring-buffer events. A repeat-offender drop in the kernel costs ~1 µs, not a userspace round-trip.
- **Userspace policy engine (`trishula-engine`, Deployment).** The engine reconstructs HTTP/1.1, HTTP/2 and gRPC, and inspects deeply. The stack: OWASP CRS evaluation via an embedded Coraza-compatible evaluator (SecLang import). A compiled Vectorscan matcher covers the hot regex subset. A **CEL-based DSL** evaluates a structured request view. OpenAPI 3.1 carries **positive-security** validation. **Bot detection** reads TLS, header and behavior fingerprints. **Per-route rate limiting** and **score-based temporary bans** complete the ladder. An in-band ML scorer carries an async escalation path.
- **Control plane (`trishula-operator`).** The operator compiles the CRDs (`WAFPolicy` / `APISpec` / `RuleSet` / `BanPolicy`) into signed bundles. The bundle carries evaluator chains, matcher DBs, kernel map values and ban thresholds. Hot reload stays within 5 s. Canary rollout, shadow mode for every change and OTel-native telemetry complete the plane. A CRS differential parity gate runs in CI.

**The reference deployment.** NGF terminates TLS at a Gateway API `Gateway`. The AI/app routes steer to Trishula as a plain `backendRef` Service. Any conformant implementation (Envoy Gateway, kgateway, Istio, Traefik) supports the same shape. Trishula is deliberately gateway-agnostic. NGF is where the contract is *proved*, not where it ends. A v2 ext_proc mode (§10.4) removes the proxy hop entirely on ext_proc-capable gateways.

**Differentiation, as specification.** The OSS WAF field is not empty. "More than OSS WAF" is a feature list, not a slogan (§2.3, §4):

1. eBPF altitude with kernel-enforced bans.
2. Positive security via OpenAPI.
3. Bot and anti-automation detection.
4. Specified, tunable, observable **temporary ban algorithms** — fail2ban-for-HTTP.
5. CRS parity enforced by a differential CI gate.
6. Developer-first authoring with CEL.
7. OTel on every surface.
8. A teach-the-web curriculum as a product feature.

<div class="pagebreak"></div>

## 2. Positioning & Non-Negotiable Design Decisions

These are **design decisions, not preferences**. The decisions keep the project from the failure shape of every prior OSS WAF: a second nginx with rules.

### 2.1 D1 — Kubernetes-native: the WAF is CRDs, not config files

- Policy lives in `WAFPolicy`/`APISpec`/`RuleSet`/`BanPolicy` CRDs. There is **no nginx.conf equivalent**: no file mounts, no sidecar config language, no bespoke REST. `kubectl apply` (via GitOps or by hand) is the entire deployment story.
- CRDs adopt the Gateway API status-condition vocabulary (`Accepted` / `Programmed` / `ResolvedRefs`). Operators see one UX across the estate.
- Rules run as RBAC-scoped, diffable, reviewable PRs. The same properties made mTLS and OAuth policy manageable.

### 2.2 D2 — Gateway API is the traffic contract; NGF is the reference proof

- Trishula participates in traffic **as a Gateway API citizen**: a Deployment-backed Service behind `HTTPRoute` `backendRefs`. The Service is readiness-gated, health-checked, weight-steerable and canary-able. The gateway owns traffic strategy. The WAF never selects endpoints.
- **Reference deployment = NGINX Gateway Fabric.** Why NGF: NGINX-org maintenance and the Apache-2.0 licence. The NGINX data plane (h2c upstreams, TLS termination, BackendTLSPolicy) is production-hardened. NGF 2.x is Gateway-API-conformant and integrates the Gateway API Inference Extension (EPP) for model-pool steering. Its security-stage documentation patterns (WAF policy attachment, guardrails processing) are the reference shapes for a Gateway. Trishula requires *nothing beyond conformant Gateway API* for its core contract. NGF is where it is proven first, with reproducible lab manifests.
- Portability is insurance, not marketing. §10.5 records the honest delta per gateway class. No commercial component sits anywhere in the reference path.

### 2.3 D3 — Detection depth: more than negative signatures

Signature matching (CRS) is the *baseline*, not the product. The shipped ladder adds five detection families beyond CRS:

```mermaid
flowchart TB
    subgraph LADDER["Detection ladder (short-circuit on first decisive verdict)"]
        S0["0. kernel verdict cache<br/>(bans + cached verdicts, ~µs)"]
        S1["1. compiled matcher<br/>(Vectorscan, µs)"]
        S2["2. CRS reference evaluator<br/>(negative security)"]
        S3["3. CEL rules over<br/>structured request view"]
        S4["4. positive security:<br/>OpenAPI schema enforcement<br/>+ API discovery"]
        S5["5. bot detection:<br/>JA4/JA4S, header order, behavior"]
        S6["6. rate + ban engine:<br/>multi-window counters, fail2ban-grade"]
        S7["7. ML scorer<br/>(local ONNX + async judge)"]
    end
    S0 --> S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7
```

*Figure 1. Seven families; every compile artifact comes from one `RuleSet`/`WAFPolicy` source.*

- **Positive security (S4):** `APISpec` CRs wrap OpenAPI 3.1 docs per (host, route-prefix). Enforce mode blocks unmatched paths, methods and param shapes. Learn mode builds specs from live traffic and emits drift diffs. Commercial WAFs sell this as their top-tier feature; OSS rarely ships it.
- **Bot detection (S5):** JA4/JA4S TLS fingerprints (terminated-hop observed), header order/entropy fingerprinting and per-source behavioral windows. The evidence feeds per-request verdicts and the ban engine's score.
- **Rate + temporary bans (S6, §13):** the fail2ban-for-HTTP algorithm of §13: specified, auditable, kernel-enforced for repeat offenders.
- **ML (S7):** local ONNX scorers run inline; heavier judges run async. Verdicts go to cache and backfill to the kernel maps (§14).

### 2.4 D4 — Developer-first: the adoptability thesis

> *iptables/ACLs, mTLS, vaults, OAuth/OIDC, SSO — every control now ubiquitous reached ubiquity by being **usable by developers**. The WAF did not. WAFs stayed appliance-shaped: opaque rule languages, out-of-band consoles, config dialects. Trishula's founding hypothesis: developer understandability **is** the security feature.*

Concretely, this thesis is enforced by five product properties:

1. **One language for custom logic: CEL.** CEL is small, well-specified, K8s-native (admission control), Envoy-familiar, cost-budgeted and sandboxed. No new DSL enters the learning path. `request.method == "POST" && request.body.?json.messages.size() > 128` is a whole rule.
2. **One config surface: CRDs + OpenAPI the developers already maintain.** Positive security derives from artifacts API teams already produce. The spec behind their SDK is the policy.
3. **One observability language: OTel.** Verdict traces, metrics and first-class OTLP logs correlate by trace ID. The team reads them in the backend it already runs — not in a vendor console.
4. **Failure semantics, one sentence per route.** The mode: fail-open or fail-closed, chosen in the `WAFPolicy`. The state: a CRD condition. The view: the trace.
5. **Docs that teach the wire (§7):** every rule example links to the bytes it inspects. The docs double as an HTTP/2, TLS and QUIC curriculum. The doc has failed when a developer does not understand why a rule fires.

### 2.5 D5 — Honesty as a mechanism: shadow-first and differential parity

Every change (rule, schema, ML model, ban threshold) ships **shadow-first**. Promotion follows evidence (matches, FP delta). CRS compatibility is enforced twice. The verdict-level differential gate runs against the reference evaluator, in CI and in production telemetry (§11.8). "Compatible" claims die quietly in every engine in this field; Trishula makes them CI failures instead. Performance targets carry the "target" label until a benchmark measures them (§17). Visibility gaps per traffic shape are documented contracts (§9.7).

### 2.6 D6 — One project, several repos: `trishula-dev` + `trishula.dev`

- **Footprint, registered 2026-10:** GitHub org [`trishula-dev`](https://github.com/trishula-dev) and the domain [`trishula.dev`](https://trishula.dev) (apex parked at the registrar; the site comes later). The upstream handle `trishula` is a dormant 2013 user account and stays unavailable. `trishula-dev` is the permanent org name. No aliasing layer is planned around it.
- **Repo split:** one product repo (`trishula-dev/trishula` — code, charts, operator, engine, shield), one site repo (`trishula-dev/website` — trishula.dev itself, static). The rules live with the code, not on a fork: `rules/cel/` and `rules/exclusions/` ship inside the product repo. Every shipped rule is parity-tested and versioned with the engine that runs it. Curated community sets move into a separate `trishula-dev/rules` repo once external contributions justify the review surface (Phase 1+ decision).
- **Domain usage stays plain:** `trishula.dev` = docs/site + project links. No domain dependencies exist in the enforcement path. The API group is `trishula.security` (CRDs). Images publish from `ghcr.io/trishula-dev/*`.
The label/annotation prefixes are `trishula.shield/*` and `trishula.security/*`. Those strings are contractual for downstream consumers and stay unrenamed, whatever the org handle reads.
- **The split is the governance boundary:** the product repo stays Apache-2.0 code-only (clean provenance for packagers and adopters). `website` and `rules` evolve as separate review surfaces on their own cadence.

<div class="pagebreak"></div>

## 3. Problem Statement

### 3.1 The estate today

The estate is a Kubernetes cluster in front of a Gateway-API data plane. The reference deployment runs NGINX Gateway Fabric:

- **Gateway tier:** TLS termination, Gateway/HTTPRoute routing and L4 edge protections: conformant Gateway API, h2c backends, weighted steering. AI estates add the Inference Extension (EPP) for model pools.
- **Application/model pools:** Deployments on HTTP/1.1, HTTP/2 or gRPC. The rising share: AI inference — long bodies, SSE streaming and token-metered endpoints.
- **A WAF, somewhere, awkwardly:** an external proxy hop with its own config language, or — in the majority of dev-run clusters — *nothing*. Adoption cost is the reason.

### 3.2 The problems, enumerated

| # | Problem | Consequence |
|---|---------|-------------|
| P1 | The WAF is a separate proxy hop on the app path | Extra latency, extra TLS/keepalive fanout, a second scaling unit, config surface nobody on the app team owns |
| P2 | Two configuration languages per security change (app manifests + WAF directives) | Security changes leave GitOps; drift between envs; the WAF console becomes shadow infrastructure |
| P3 | Rules are not Kubernetes-native | No GitOps diff, no RBAC-scoped authoring, no canary of a rule change, no CRD status |
| P4 | The WAF cannot see kernel-level context | Connection-level abuse (slowloris, credential stuffing across connections, floods, bot patterns) is evaluated per-request only — or not at all |
| P5 | OSS WAF depth stops at negative signatures | No positive security, no API discovery, no bot/anti-automation defense, no rate-based ban workflows — the features that separate a WAF from a regex filter |
| P6 | AI traffic has unmet detection needs | Prompt-injection/jailbreak and exfiltration semantics are invisible to regex-era rules; ML is bolt-on rather than in-band |
| P7 | The developer experience is hostile | Rules are written in vendor dialects, tuned over weeks, opaque to the people whose APIs they protect; the practical outcome is that **devs skip the WAF entirely** |
| P8 | Temporary bans are ad hoc | Every OSS remedy is a shell script grepping logs (or fail2ban on nginx logs — log parsing on tap for a wire problem); no spec, no observability, no kernel-speed enforcement |

### 3.3 Why not: the alternatives, honestly

- **Keep an nginx WAF tier (ModSecurity/NGINX-App-Protect-class):** the choice keeps every problem P1–P8. The shape *is* P1/P2/P3/P7. ModSecurity is EOL on nginx[316], and libModSecurity is maintenance-mode[318]. The OSS community's CRS work now lives on Coraza[310].
- **Cilium + Envoy:** excellent network policy and L7 authorization, yet not a WAF. The gaps: no CRS evaluation, no body-inspection depth, no security rule lifecycle, no bot defense. Its *architecture* (eBPF fast path + userspace L7 proxy) is the validated pattern this design borrows deliberately[85][87].
- **Commercial cloud WAAP:** it contradicts the open-source, self-hosted requirement and sends payloads to third-party inspection. Model payloads and regulated estates rule it out.
- **open-appsec / SafeLine (OSS ML WAFs):** the closest prior art in detection depth. open-appsec couples a learning engine to enforcement with CRDs; the coupling runs through a central management plane[192][239]. SafeLine is container-nginx-shaped with a semantic pipeline[196][205]. Neither carries an eBPF data plane. Neither speaks the Gateway-API steering contract. Neither treats developer comprehensibility as a design target.
- **fail2ban / CrowdSec style remediation:** the right *idea* (score behavior, ban temporarily, unban on evidence) at the wrong altitude. The wrong parts: log parsing after the fact; filesystem state; no HTTP-native view; no per-route policy. Trishula moves the idea onto the wire, into the kernel and into the CRD (§13)[145][147].

### 3.4 Target users

- **Application/ML platform developers (primary):** declare `APISpec` and `RateLimit/BanPolicy` for their own endpoints. They read verdict traces and write CEL rules. A WAF dialect never enters their learning path.
- **Security engineering:** curates `RuleSet` CRs and CRS bundles. They tune in shadow mode and own detection quality telemetry.
- **Platform/SRE:** steer routes via Gateway API. They scale Trishula like any Deployment/DaemonSet and own the SLO dashboards.

<div class="pagebreak"></div>

## 4. Related Work — What We Borrow, Where We Sit

*This section surveys the WAF-shaped core. Appendix E surveys the wider field. The coverage: eBPF security tools, runtime-enforcement platforms, gateway/plugin stacks and the temporal-ban lineage. Each project carries its "why we did not build on it" record.*

### 4.1 The field, in one table

| Project | Engine | Rules / Detection | ML | K8s shape | Developer DX |
|---------|--------|-------------------|----|-----------|--------------|
| Coraza | Go library | CRS-compatible (SecLang), WASM plugins[133][134] | no | embed / Caddy module / HAProxy SPOA | lib-first; you write glue |
| ModSecurity (libMOSC v2) | C library | CRS native | no | nginx/Apache module | EOL on nginx[316]; maintenance mode[318] |
| SafeLine | container stack (nginx core) | signatures + semantic pipeline | semantic + optional LLM | docker-compose first | panel-first; nginx underneath[196][209] |
| open-appsec | attachment + central engine | positive security + signatures | 2 ML models + context | K8s CRDs, central mgmt | CRDs yes; central plane couples you[192][239][241] |
| BunkerWeb | nginx-based | CRS + own | no | containers | template-first |
| CrowdSec | Go agent + remediation comps | own rules + CRS bridge; community blocklists; bot detection[145][170] | community IP intel | agent + local API | great CLI story; log-tap altitude |
| fail2ban | log-parsing daemon | pattern → temporary ban | no | host services | the UX archetype for bans, on the wrong altitude[147] |

### 4.2 What Trishula borrows (with credit)

- **Coraza as embedded reference evaluator** — composition, not fork: CRS/SecLang parity, WASM extension surface[134][154][312].
- **open-appsec's learning→enforcement lifecycle** — minus the central-plane coupling[239][237][241].
- **SafeLine's staged semantic pipeline** — cheap deterministic stages precede the heavier semantic analysis[205][206].
- **CrowdSec's community telemetry idea** — crowd blocklists as one ban-engine input; optional and CRD-gated[145][170].
- **fail2ban's temporal ban UX** — score thresholds, temporary bans with expiry, an evidence-driven release. The re-spec for HTTP runs at wire speed (§13)[147].
- **Cilium's two-plane architecture** — eBPF fast path + userspace L7 proxy, the proven decomposition for exactly this problem[85][87].

### 4.3 Where Trishula sits — the gap no project occupies today

```mermaid
quadrantChart
    title OSS HTTP security landscape (illustrative)
    x-axis "Per-request depth (regex) --> Full detection stack (positive/bots/rates/ML)"
    y-axis "Host/app-shaped --> Kubernetes-native"
    "Coraza": [0.55, 0.35]
    "SafeLine": [0.7, 0.25]
    "open-appsec": [0.8, 0.55]
    "CrowdSec": [0.35, 0.3]
    "ModSecurity": [0.4, 0.2]
    "Trishula (target)": [0.9, 0.9]
```

*Figure 2. Trishula's target quadrant: a full detection stack, Kubernetes-native, with kernel altitude — and authored by developers.*

- **One rule surface compiles across altitudes** (kernel maps + matcher DB + evaluator chain). No OSS WAF in the survey compiles this way.
- **eBPF shield as a first-class component** (shield-only mode hardens paths that keep their existing gateway).
- **Gateway-API-native steering posture** proved on NGF.
- **CRS differential parity as a product feature** (§11.8) — more than a test add-on.
- **Specified temporary-ban algorithm with kernel enforcement** (§13) — absent from every project in the table above.
- **A teach-the-web curriculum as a deliverable** (§7) — SPIFFE/SPIRE treat docs as the product. No WAF carries the same choice.

<div class="pagebreak"></div>

## 5. Developer Experience Charter

The charter is testable: each commitment below carries a CI check or an acceptance test. A break is a bug with the same severity as a detection miss. The thesis of §2.4 stands behind the severity: *understandability is the security feature*.

| # | Commitment | Test that enforces it |
|---|-----------|----------------------|
| DX1 | A developer's first custom rule ships in ≤ 15 minutes from `git clone` (lab: kind + NGF + Trishula + one CEL rule, fixture-verified) | CI runs the lab script nightly; timing asserted |
| DX2 | Every CEL rule error message names the offending field and suggests the structured-view path | fixture corpus → assert error text shape |
| DX3 | Every documented rule links to the wire-level explainer (§7) for the fields it touches | docs lint: backlink check per example |
| DX4 | No rule requires vendor-dialect knowledge (no ModSec directives exposed unless importing CRS) | docs lint + API review gate |
| DX5 | A blocked request surfaces a self-explaining verdict: rule ID, plain-language reason, link to the rule's doc + fixture request | golden trace tests over verdict telemetry |
| DX6 | Removing Trishula returns the cluster to the pre-install state with zero kernel residue | uninstall CI job runs `bpftool` assertions |
| DX7 | All docs examples run — fixtures are CI-executed, never decorative | fixture runner over docs corpus |

The developer's path, in one picture:

```mermaid
flowchart LR
    subgraph DAY0["Day 0 — install (one Helm/manifest install, kind-lab first)"]
        A["helm install trishula<br/>(operator + shield + engine)"] --> B["verify: NGF steers to engine;<br/>shield ready labels on all nodes"]
    end
    subgraph DAY1["Day 1 — protect an app"]
        C["APISpec from your<br/>existing OpenAPI 3.1"] --> D["WAFPolicy: bind routes,<br/>fail-open|closed, ban tier"]
        D --> E["observe: shadow verdicts<br/>in your OTel backend"]
        E --> F["promote to enforce<br/>(evidence-gated)"]
    end
    subgraph DAY2["Day 2 — own it"]
        G["PR: CEL tweak / schema drift<br/>/ exclusion / ban threshold"] --> H["shadow → promote<br/>(same CRD, same git)"]
    end
    DAY0 --> DAY1 --> DAY2
```

*Figure 3. The adopter lifecycle the deliverables must support. No step requires a step away from Kubernetes or Git.*

<div class="pagebreak"></div>

## 6. Vision, Goals, Non-Goals

### 6.1 Vision statement

> Every HTTP request entering a Kubernetes cluster is inspected at line rate. The policy lives in Git. The developer who wrote the API understands it. The eBPF shield acts before the request costs a scheduler tick. The engine evaluates CRS, positive schemas, bots, rates and ML on one path. Any Gateway-API data plane steers to it like any other backend.

### 6.2 Goals

**G1 — Inline without a proprietary hop.** Trishula sits between the gateway and pools as a Deployment-backed Service. Any conformant Gateway-API implementation steers to it. **NGF is the reference proof, validated in CI.**

**G2 — eBPF speed where it counts.** The XDP/TC fast path carries L3/L4 ACLs, flood defense, cached verdicts and **ban-table enforcement** in kernel. Deep inspection runs in userspace, co-located on the same node behind a shared ring buffer. The targets live in §17.

**G3 — CRS compatibility as the correctness baseline.** The engine imports and evaluates OWASP CRS (incl. SecLang) with verdict-level parity (§11.8). A compiled fast-path matcher covers the hot subset. Differential shadow mode catches any fast-path regression against the reference evaluator.

**G4 — A rule language engineers want to use.** CEL runs over the structured request view. SecLang import serves the CRS estate. Hot reload runs via CRD apply. Evaluation carries a cost budget.

**G5 — Positive security.** OpenAPI 3.1 schema enforcement carries discovery/learn mode and drift telemetry. The enforcement derives from specs developers already maintain.

**G6 — Bot defense and anti-automation.** The stack: JA4/JA4S, header-order and entropy fingerprints, behavioral windows. Per-detector verdicts feed the inline decisions and the ban engine (§12).

**G7 — Rate limiting and temporary bans as specified mechanisms.** Multi-window sliding rates run alongside score-based temporary bans with expiry and evidence-driven release. The design is fail2ban-for-HTTP, kernel-enforced for repeat offenders (§13).

**G8 — ML with a clean hand-off contract.** Feature views derive from engine + eBPF events. Local ONNX scoring runs in-band under a 1 ms budget. Heavier semantic judges run async with verdict caching (§14).

**G9 — Observable by default, in OTel.** OTLP traces, metrics *and logs* ship as the default. Every verdict is a correlated span. Shields export kernel counters. Per-route dashboards ship in-repo (§15).

**G10 — Teach the web.** The docs, labs and curriculum of §7 are a first-class deliverable of the project, SPIFFE/SPIRE-style.

### 6.3 Non-goals (the standing boundary)

- **Not a TLS-terminating edge LB** for the whole estate. The gateway owns termination in the reference deployment. Trishula inspects post-termination plaintext. Re-encrypting engine termination is a secondary, feature-gated mode. TR-203 L3 carries the mode one opt-in leg: the `--h3-listen` flag opens the inline QUIC/HTTP-3 listener (`cmd/engine/h3.go`; [ADR-0006](adr/0006-inline-h3-listener.md)). The TLS listener's responses advertise the h3 alternative (Alt-Svc). The engine's own ladder serves the h3 requests. The flag off binds no UDP socket; the gateway-terminated path stays the default.
- **Not a Service Mesh:** east-west policy stays with Cilium/network policy. Trishula is the north-south + steering-path control.
- **Not a secrets/token vault:** Trishula references JWT claims. It stores nothing and tokenizes nothing.
- **Not an endpoint-picker:** model-pool selection stays with EPP/the gateway. Trishula proxies transparently and preserves the downstream selection.
- **No Windows or other-kernel ports**: Linux (XDP/TC) only.
- **No vendor console:** there is no Trishula web UI. The CRDs, kubectl and the team's OTel backend are the console. (A read-only dashboard preset ships as Grafana JSON, not an app.)

### 6.4 Success metrics

| Metric | Target |
|--------|-------------|
| Added latency, inline vs direct (p99, full CRS + 8KB body) | ≤ 1.5 ms |
| Fast-path verdict (cached block/allow/ban, kernel) | ≤ 100 µs added |
| Throughput per engine replica (4 vCPU, CRS + schema) | ≥ 10k req/s |
| Shield drop rate (XDP, native driver, commodity 25G NIC) | ≥ 10 Mpps/core |
| CRS verdict parity vs reference evaluator on CRS test suite | 100% applicable rules |
| False-positive-rate delta vs plain CRS defaults | ≤ 0 (parity baseline) |
| ML local verdict overhead (in-band ONNX, CPU) | ≤ 1 ms p99 |
| Time-to-enforce a `RuleSet` CR (apply → all replicas) | ≤ 5 s |
| DX1 lab time (clone → first enforced rule) | ≤ 15 min |
| Docs examples CI-executed | 100% |

<div class="pagebreak"></div>

## 7. Teach-the-Web Curriculum

The SPIFFE/SPIRE lesson: the project that explains *why the wires work* becomes the reference implementation people trust. Trishula's docs therefore include a curriculum. The delivery: a docs section + runnable labs (kind clusters with scripted scenarios). The curriculum is maintained **in-repo**, with the same CI as product code.

### 7.1 Curriculum map — what each layer of the product teaches

```mermaid
flowchart TB
    subgraph C1["Module 1 — The wire: HTTP/1.1 & HTTP/2"]
        A1["framing, keep-alive, chunked TE"] --> A2["h2 streams, HPACK, multiplexing"] --> A3["smuggling: CL/TE conflicts (why the parser is strict)"]
    end
    subgraph C2["Module 2 — TLS & QUIC"]
        B1["handshake, ALPN, SNI"] --> B2["JA4/JA4S: why fingerprints survive encryption"] --> B3["QUIC: what moves into UDP, 0-RTT risks"]
    end
    subgraph C3["Module 3 — eBPF as a platform"]
        C1a["XDP/TC hooks: where packets meet programs"] --> C1b["maps, ring buffers, verifier bounds"] --> C1c["why L7 does not live in kernel (verifier + ciphertext)"]
    end
    subgraph C4["Module 4 — Security modeling"]
        D1["negative vs positive security"] --> D2["anomaly scoring (CRS) and why PLs exist"] --> D3["bots: fingerprints vs behavior"] --> D4["rate algorithms & ban ladders"]
    end
    subgraph C5["Module 5 — The frontier: HTTP/3, PQ, AI abuse"]
        E1["HTTP/3/QUIC ingress posture"] --> E2["post-quantum: hybrid key exchange, PQ TLS on the path"] --> E3["AI request/response abuse classes"]
    end
    C1 --> C2 --> C3 --> C4 --> C5
```

*Figure 4. Five modules, each anchored to a real component a learner can `kubectl` into.*

### 7.2 The pedagogy rules

- **Every rule example cites its wire anatomy.** A CEL rule on `request.headers` links to the header explainers (Module 1). The JA4 bot rule links to Module 2's fingerprint lesson. §13's ladder links to the rate-algorithm lesson (token bucket vs sliding window vs EWMA, with interactive fixtures).
- **Labs are runnable clusters,** not diagrams: `lab/` scenarios replay recorded adversarial traffic against live kind clusters. Module 1's smuggling corpus is exactly the differential corpus of §11.8.
- **The product is the textbook:** when a rule fires, the verdict's trace metadata carries the module link (DX5). Developers read at incident time.
- **PQC is in scope from the first docs cut** (not the data plane). Hybrid key exchange is the curriculum core: X25519+ML-KEM, the IETF-standardized hybrid group [324]. Hybrid groups are default in mainstream TLS stacks and browsers since 2024–2025 [325][326]. The curriculum locates the PQ effects on Trishula's path. The gateway terminates TLS. PQ therefore affects the gateway↔client handshake and the gateway↔pool mTLS choices. Appendix A carries the 4 product-side notes. It covers the ClientHello size effect and the JA4 fingerprint effect [327][328]. It states what a WAF must not assume about payload visibility under future TLS revisions.

### 7.3 Deliverables

| Deliverable | In | Version |
|------------|----|---------|
| Five teaching modules (docs) | `docs/academy/` | modules 1, 3, 4 at rc3 |
| Kind-lab scenarios + fixtures | `lab/` | modules 1, 3, 4 at rc3; modules 2, 5 shipped at the rc3 cut |
| "Why did this block?" verdict-doc generator | engine | ties verdict → rule → module (§15 OTel schema) |
| Adversarial corpora as teaching sets | `test/corpora/` | shared with §11.8 differential suite |

<div class="pagebreak"></div>

## 8. Architecture

### 8.1 Design principles

1. **The kernel does the cheap thing; the userspace plane does the smart thing.** Every packet pays at most one XDP/TC hook. Anything needing full HTTP parsing pays the one ring-buffer hop. The rule engine then loops freely in userspace.
2. **One policy artifact, many enforcement altitudes.** A `RuleSet` compiles simultaneously to (a) userspace evaluator chains, (b) a Vectorscan matcher DB for the hot subset, (c) kernel map values — ACLs, verdict caches, **ban tables** — and (d) OTel counters. One source of truth, no drift.
3. **Steering belongs to the gateway.** Trishula never selects endpoints; it is a steerable, health-checked backend under any conformant Gateway-API implementation. Weights, canaries and session persistence stay in Gateway API land.
4. **CRDs are the only config surface.** No file mounts, no sidecar config, no bespoke REST. `kubectl apply` is how a rule deploys.
5. **Every change can run in shadow.** New rules, ML models, schema versions and ban thresholds evaluate verdict-only first. Promotion requires evidence (matched-count, FP delta).
6. **Fail-open or fail-closed is a per-route CRD choice** (default fail-open in shield mode; per-`WAFPolicy` inline).

### 8.2 Component map

```mermaid
flowchart TB
    subgraph KERNEL["Linux kernel (per node, DaemonSet)"]
        XDP["XDP @ NIC<br/>L3/L4 ACL, floods,<br/>ban tables"] --> TC1["TC @ eth0/veths<br/>flow classification"]
        TC1 --> RING["BPF ring buffer<br/>events"]
    end
    subgraph USERSPACE["trishula-engine pods (Deployment)"]
        PS["Parser<br/>HTTP/1.1, HTTP/2, gRPC, WS"] --> RE["Rule engine ladder<br/>CRS + CEL + compiled"]
        RE --> SCHEMA["OpenAPI validator<br/>(positive security)"]
        RE --> BOT["Bot detectors<br/>(JA4, headers, behavior)"]
        RE --> RATE["Rate + ban engine<br/>(multi-window)"]
        RATE --> BANT["Ban store<br/>(kernel tables + userspace ledger)"]
        RE --> ML["ML scorer (ONNX, local)"]
        ML --> ASYNC["Semantic judge (async)"]
        VC["Verdict cache"]
    end
    subgraph CONTROL["trishula-operator"]
        CRDS["WAFPolicy / APISpec /<br/>RuleSet / BanPolicy CRDs"] --> COMP["Compiler: evaluator +<br/>matcher DB + kernel maps"]
    end
    COMP -->|"maps + ban tables"| KERNEL
    COMP -->|"signed bundles"| USERSPACE
    PS --> OBS["OTel: traces + metrics<br/>+ OTLP logs"]
```

*Figure 5. Component map: per-node shield, userspace engine, CRD compiler — ban state flows kernel-ward for line-rate enforcement.*

The stack is deliberately three deployables:

- **`trishula-shield` (DaemonSet, privileged).** The loader attaches XDP at the NIC and TC at node/pod interfaces (cilium/ebpf Go loader, CO-RE objects). It owns the XDP shield, the flow classification and the kernel ban-table enforcement. It exports the ring buffer and the pinned maps. Host-network pod; no service port.
- **`trishula-engine` (Deployment + Service).** The userspace WAF terminates the steering hop (plaintext from the gateway, or TLS it re-terminates itself in secondary mode). It runs the full ladder (§2.3) and forwards upstream. The engine scales horizontally. Each replica drains the co-located shield's ring buffer (verdicts are content-keyed, so per-flow affinity is unnecessary).
- **`trishula-operator` (Deployment).** The operator watches CRDs. It compiles bundles (userspace + matcher DB + map values + ban thresholds) and rolls them via a signed bundle API. It manages the shadow lifecycle, exposes status Conditions and records FP-feedback telemetry.

### 8.3 Request lifecycle

1. **Client → Gateway.** The gateway (reference: NGF) terminates TLS, applies edge policy, matches the `HTTPRoute`.
2. **Gateway → Trishula Service.** Protected routes' `backendRefs` point at `trishula-engine`. The gateway health-checks the Service like any backend.
3. **Trishula ingress hook (TC).** The same-node TC classifier tags the connection. It feeds cheap pre-connection metadata (SYN rate, ban-table hits, source reputation) into the engine.
4. **Engine parse** → structured request view → **evaluation ladder** (§2.3). The parse path runs the conformance gate first ([TR-44](https://github.com/trishula-dev/trishula/blob/main/docs/design/protocol-conformance-verdict.md); TR-199). The gate rejects the h1 framing-ambiguity classes at the parse path. The classes: `Content-Length` + `Transfer-Encoding` together; duplicate `Content-Length` values (RFC 9112 [section 6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1), [section 6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)). The reject resolves pre-CRS as the `block` verdict with a parse-layer rule id (`http1:framing-cl-te`, `http1:framing-dup-cl`). The corpus rows and the verdict cells pin it (`test/crs-differential`, the CRS differential parity gate below). The ladder walks in order:
kernel-cached verdicts/bans (hit ≈ no-op); the compiled matcher (µs); full CRS evaluation; CEL rules;
schema validation; bot scoring; rate/ban checks; ML scoring.
It short-circuits on the first decisive verdict, by the policy's action precedence (`block > challenge > log > pass`). SecLang `matcaction` overrides stay preserved for imported rules.
5. **Verdict.** allow: forward upstream (transparent proxy, preserving headers/metadata end to end — no endpoint-picking logic lives here). block: emit a local response (per-route configurable body; `429` for bans, with `Retry-After`). challenge: issue an evidence request (§13). log/shadow: mark and continue.
6. **Response path.** Response headers and bodies re-inspect on the response chain (CRS phase 4). Inspection is streaming-aware, with bounded chunk buffering. Exfiltration patterns are checked on chunk boundaries.
7. **Telemetry.** One OTel span covers each request across all stages. Kernel counters export every tick. Every verdict carries rule IDs, phase and score ladder (§15).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant GW as NGF Gateway
    participant XDP as Shield XDP (node NIC)
    participant ENG as trishula-engine
    participant TC as Shield TC (node veth)
    participant POOL as App/model pools

    C->>XDP: TCP SYN (TLS)
    XDP->>XDP: LPM ACL + flood check + ban table + verdict cache
    XDP->>GW: pass (marked)
    Note over GW: terminates TLS, matches HTTPRoute<br/>(route backendRef = trishula-engine)
    GW->>ENG: HTTP/1.1 or h2c request
    ENG->>TC: packets cross engine-node veth
    TC->>TC: classify, ban-table probe, rate counters
    TC-->>ENG: ringbuf event (metadata only)
    ENG->>ENG: parse → ladder (CRS/CEL/schema/bots/rates/ML)
    alt verdict = allow
        ENG->>POOL: forward (streamed response inspected)
        POOL-->>ENG: response
        ENG-->>GW: response
    else verdict = block / ban
        ENG-->>GW: 403 / 429 (Retry-After) with ban telemetry
    end
```

*Figure 6. Inline path: the kernel plane touches the flow at two altitudes; the engine owns decisive inspection; bans feed back kernel-ward (dashed return paths omitted for legibility).*

### 8.4 Operating modes

- **Shield-only:** DaemonSet alone. XDP/TC drops obvious L3/L4 abuse, enforces ban tables and (on plaintext legs) trivial L7 patterns. Zero proxy hop; drop-in hardening of any existing path.
- **Inline (the default for protected routes):** full engine as the steered backend.
- **Shadow-parallel:** the engine evaluates but forwards regardless. The mode serves CRS-import confidence, rule canary, ML learning and migration diffs.
- **Schema-learn:** APISpec discovery reads live traffic and emits OpenAPI diffs for review.

### 8.5 Deployment topologies

```mermaid
flowchart LR
    subgraph CL["Cluster"]
        GW["NGF Gateway<br/>(probes, steers)"] --> ENG["trishula-engine svc<br/>(Deployment)"]
        ENG --> POOL1["model pool A"]
        ENG --> POOL2["pool B"]
        DS["trishula-shield<br/>DaemonSet: every node"] -.->|"ring buffer"| ENG
    end
    C["client"] --> GW
```

*Figure 7. Topology: gateway front door, engine as steered backend, shield on every node.*

Two placements are supported. **(a) A dedicated engine tier:** a Deployment sized for throughput; the shipped shape (2026.01) — the simplest scaling story. **(b) A fused sidecar:** the engine container sits beside the gateway container on a shared loopback. That shape carries the lowest latency; the coupling is higher — a later option. The shield DaemonSet stays mandatory in both.

<div class="pagebreak"></div>

## 9. eBPF Packet Path

### 9.1 The two-plane principle

Trishula splits inspection by altitude:

- **Kernel plane (shield):** bounded, allocation-free, verdict-cheap. The duties: L3/L4 ACLs, flood defense, ban-table enforcement and flow classification. The kernel classifies most packets and counts them — O(1) work per packet.[60][61]
- **Userspace plane (engine):** unbounded parsing freedom (loops, allocs, regex, ML) in a language with an ecosystem (Go). Full HTTP reconstruction happens exactly once per request, here.

The kernel deliberately does **not** do: full header walks, body parsing, regex evaluation or TLS. Two hard reasons stand. One is verifier boundedness. Loops and instruction budgets make real L7 parsing a tail-call-bound project, with poor maintenance economics[96][106][105]. The other is ciphertext: at the NIC, HTTP(S) payloads are TLS records[79]; decisive L7 analysis requires post-termination plaintext. The kernel plane still gets a *bounded* plaintext fast path (§9.6) on legs where the gateway already terminated TLS. It never depends on that path.

### 9.2 Hook inventory

| Hook | Where | Current duties | Later |
|------|-------|-----------|-------|
| **XDP (native/generic)** | shield node NICs | L3/L4 ACL (LPM trie maps), SYN/UDP flood tarpits, verdict-cache + **ban-table** enforcement, IPv4/IPv6 normalization | AF_XDP for shield-only mode, cpumap steering |
| **TC ingress/egress** | engine-node veths + node eth0 | flow classification, mark-based steering recognition, per-flow behavioral counters, plaintext fast-path probe, ringbuf events | sockmap/sk_msg redirect for same-node acceleration |
| **cgroup/connect hooks** | engine pods | upstream connect-time policy (pool allow-list), connect marks | — |
| **kprobes** | nodes (observability) | conntrack quality, retrans/RTT hints for behavioral DoS | — |
| **uprobes** | optional, per-workload | SSL_read/SSL_write tracing where termination happens inside an app pod | Go crypto/tls uprobes |

All C compiles CO-RE (vmlinux.h from `bpftool btf dump`). The Go shield loads it with cilium/ebpf. Objects are generated in CI via bpf2go, so a tagged release ships byte-identical objects.[94][126][95]

TR-203 L1 (2026-10-25): the UDP/QUIC kernel abuse class ships at both hooks ([TR-200 #242](https://github.com/trishula-dev/trishula/issues/242), leaf 1 of [#264](https://github.com/trishula-dev/trishula/issues/264)). XDP counts per-source datagrams in `rate_windows` and drops past the published threshold ([the rate accounting](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#95-kernel-side-rate-accounting-feed-13)). A live `ban_table` row drops the UDP flow first, at both hooks. TC rows count the UDP flow (datagram count, payload bytes, window stamps) — the same `flow_stats` shape ([the map set](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state)). Both hooks fail open: a missed knob row, a missed insert or an expired verdict passes the datagram. The kernel counts datagrams and drops; it reads no QUIC frames ([the two-plane principle](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle)).

### 9.3 Maps and state

| Map | Type | Size | Producer → Consumer |
|-----|------|------|---------------------|
| `acl4`/`acl6` | LPM trie | 1M prefixes | operator → shield (compiled from CRDs) |
| `verdict_cache` | LRU hash | 1M entries, TTL | engine → shield (block/allow with expiry) |
| `ban_table` | LRU hash + array | 1M entries, TTL | **ban engine → shield** (banned keys with expiry + reason code) |
| `src_rep` | LRU hash | 256k, scored | engine → shield (reputation: stuffing scores, bot scores) |
| `flow_stats` | LRU hash | 256k | shield → shield (per-flow seg/byte counters, slowloris math) |
| `rate_windows` | per-CPU array + LRU | — | shield (SYN/req-rate EWMA per prefix — kernel-side rate accounting) |
| `events` | ringbuf | 16 MiB/node | shield → (co-located engine or relay) |

Cross-pod sharing: the shield pins maps on host BPFFS (`/sys/fs/bpf/trishula/`). Engine pods node-affined to shield nodes mount BPFFS read-write (hostPath). They open the pinned maps and ring directly — zero network hop for co-located engines. Non-co-located engines receive events via the shield's gRPC relay (sampled under load). **Verdict authority stays userspace.** The engine decides; the shield enforces (open question §20.3.3; the kernel stays decision-free).

### 9.4 Ring buffer sizing and backpressure

Ring events carry a fixed 128B header + optional bounded slices (path hint, JA4-style fingerprint fields). Sizing: 16 MiB default. The relay samples (1/2^k) when consumers lag. An always-sampled high-priority class carries ban writes, cache hits and block decisions. The ring is never the payload path (§9.1). Loss is then a telemetry-quality issue, surfaced as `trishula_shield_ring_dropped_total`.

TR-194 (2026-10-25): the stage-stamp bitmap grows the event wire to 208 bytes (+8 = 4.00%). The 16 MiB ring holds 80,659 records (from 83,886 at 200 bytes; −3.85%). The decoder reads both sizes; a landed record reads an all-absent bitmap.

### 9.5 Kernel-side rate accounting (feed §13)

The shield keeps cheap per-source EWMA counters (`rate_windows`), sampled at XDP/TC. The signals: SYN rates, UDP rates and post-termination request-start rates on plaintext legs. The counters are *inputs* to the engine's ban algorithm (§13.3) and a *fast-path veto*. The engine writes a ban; the kernel enforces it without further userspace consultation. Kernel counters alone never issue a ban; they escalate evidence. A SYN-flood EWMA burst pre-scores the source for the engine's decision.

### 9.6 Plaintext fast path in kernel (bounded, honest)

After gateway termination, requests crossing engine-node veths are plaintext. The TC hook works within verifier budget:

- match method via 4-byte load compare (`GET `, `POST`, `PUT `, …) on the first line;
- path-prefix gate via LPM/trie map keyed on the first N bytes (engine-compiled allow/deny/observe per route prefix);
- detect obvious anomalies (first-line oversize, missing version token, bare 0x00/CR in method, duplicate CL headers in the bounded window);
- tag the event with a `fastpath` classification so the engine can skip redundant parsing for allow-listed prefixes.

It cannot: walk all headers, parse bodies or evaluate regex. Every fast-path classification is advisory. The engine re-parses authoritatively. Kernel-vs-engine classification diffs feed the §11.8 parity gates.

### 9.7 Visibility contracts per mode

| Traffic shape | Shield sees | Engine sees |
|---------------|-------------|-------------|
| Gateway-terminated (reference) | ciphertext + flow metadata | full plaintext |
| Engine-terminated client QUIC (the opt-in h3 listener, TR-203 L3) | UDP ciphertext + flow metadata | full plaintext (the engine's own h3 view; the ladder serves the request) |
| Plaintext north-south HTTP | full plaintext (fast path §9.6) | full plaintext |
| Re-encrypted engine→pool (secondary mode) | ciphertext | full plaintext (engine terminates the steering hop) |
| kTLS/app-internal TLS (no proxy hop) | ciphertext + metadata | nothing — documented gap; optional uprobes restore visibility per workload |

**TLS visibility without keys (posture):** eBPF cannot decrypt TLS without key custody. Record framing is visible; payload bytes are not. No kernel mechanism changes that. Two operating models follow. **Model A (kernel plaintext via kTLS handoff):** the scope is where Trishula owns TLS termination: the secondary mode (§6.3), or pod mTLS. The control plane performs the handshake and holds the session keys. It hands Tx/Rx crypto state to the kernel (`TLS_TX`/`TLS_RX` ULP). `strparser` + the socket layer then observe decrypted, message-delineated plaintext. The full fast path of §9.9 applies. The price is kernel-resident session keys. Threat model, blast radius and rotation sit in the §9.9 design-note gate. **Model B (no-key):** when termination is external to Trishula, kernel-side detection is metadata-only. The metadata plane carries the pre-encryption `ClientHello` (SNI, ALPN, JA3/JA4 fingerprint bytes). Certificate-chain metadata and TLS record framing (sizes, timing) feed behavioral and rate/ban policy. Header/body policies, CRS payload evaluation and positive-schema checks are unavailable in Model B. Enforcement is limited to connection- and fingerprint-level verdicts. Extracting keys from application memory out-of-band (SSLKEYLOGFILE-style harvesting) is an anti-pattern. It is explicitly out of design scope.

### 9.8 Go-side stack choices

- cilium/ebpf carries loading, pinning and map I/O. bpf2go produces the compile-in-CI objects. `testenv` serves the verifier tests.[94][126]
- The ring reader uses a per-CPU batching channel → transaction assembler. The reader is zero-copy where the API allows. The hot path targets one allocation per request.

<div class="pagebreak"></div>

### 9.9 Socket-plane L7 fast path (a tracked evaluation; no runtime commitment)

The §9.1 principle keeps the kernel decision-free. A complementary option sits one altitude up, at the socket layer. The stack already provides TCP reassembly and TLS record processing there. This subsection specifies the tracked evaluation: what could be offloaded, under which constraints, and what it must not claim.

**Mechanism (precedent: Beeline synthesis):** the mechanism attaches data planes at `SK_SKB` (ingress/egress) and `SK_MSG` (local). `strparser` delineates the application-layer messages. kTLS handoff (Model A, above) supplies decrypted plaintext where termination is Trishula-owned. Policies are synthesized into per-policy `Parse–Match–Action` eBPF programs. The pieces:
DFA-based header extraction into a bounded header vector; compiled `if`-chain matching;
a small action-template library (`compare`, `read/write`, `en/decode`, `en/decrypt`, `hash`, `get/set`, `forward`, `drop`). Every action sequence terminates in `drop` or `forward`. Published results measure this design class: 89% of observed L7 service-mesh policies are enforceable without kernel changes. The median request-latency reduction reaches up to 6×. Throughput reaches up to 3× versus an L4-fast-path service proxy. The maximum offloadable policy complexity carries a ≥39% throughput advantage.

**What Trishula would offload (policy subset):**
- JWT HS256 authentication (`issuer`/`audience` claims)
- RBAC allowlists (source IPs, ports and paths)
- header mutation
- route marking and telemetry counters

Every class is already named in §11's ladder; every class is header-class and body-free. CRS/Coraza body evaluation is *never* kernel work. The fast path is an enforcement layer for header-class policies, not a kernel WAF.

**Architecture integration:** the fast path consumes the same single compiled bundle (§8.1.2). A `WAFPolicy` subset compiles to policy-specific eBPF templates. The rest routes transparently to the engine slow path.
The altitude fails open: a parse error or match miss forwards. The fast path never silently drops on its own failure. Verdict/ban state shares the §9.3 maps, so XDP and socket planes enforce one verdict authority. The kernel-module dependency is a gate. Hash/encode helpers are absent from the eBPF runtime on current kernels (upstream kfunc coverage is evolving). A minimal out-of-tree module is the interim precedent, with its own supply-chain and verifier-CI cost. The design note decides adopt, adapt or skip.

**Recorded constraints:** HTTP/2 requires the header cache disabled on workloads (Huffman coding stays supported). Stream-wise routing falls to the control plane for frames with ambiguous destinations (push promise, connection-wide flow control). Non-event-driven policies (health checking) and body (de)compression classes route to the slow path. HTTP/3/QUIC is out of scope with the rest of the kernel-side HTTP/3 posture (Appendix A).
- All kernel numbers (Mpps-class XDP figures, ring latency) trace to Appendix C sources[60][75][72]. Internal budgets are targets pending PoC validation (§17).

<div class="pagebreak"></div>

## 10. Gateway API Integration — NGF Reference Deployment

### 10.1 Why NGF, specifically

The reference deployment must be all-OSS, with no exotic component in the path. **NGINX Gateway Fabric (NGF):**

- open source (Apache-2.0, NGINX core data plane); maintained under the NGINX org on an active release cadence (2.x line). NGF 2.7 is fully conformant with Gateway API 1.6 and carries `HTTPExternalAuthFilter` plus TLS listener `Terminate` mode[F-ngf27];
- a hardened NGINX data plane with h2c upstreams, weighted `backendRefs` and header/canary matches. Everything Trishula's steering contract needs is core HTTPRoute semantics;
- documented integrations for the 2 patterns Trishula composes with. Pattern 1: security stages attached to routes (the WAF-for-NGINX policy attachment pattern, `securityLogs` pipelines)[254][301]. Pattern 2: the Gateway API Inference Extension (EPP) for model-pool steering[39];
- a documentation style (per-feature how-tos with manifests) that Trishula's own reference docs follow. Developers copy-edit instead of translate.

Trishula requires **no NGF-specific features** for the core contract: everything below is conformant Gateway API. NGF is where the contract is proven, versioned and gate-guarded. The same manifests run on other conformant data planes (§10.5).

### 10.2 The contract: Trishula as a Gateway API citizen

Every protected route expresses its relationship to the WAF in ordinary Gateway API objects:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: chat-completions
  namespace: ai-platform
  annotations:
    trishula.security/policy: chat-completions   # explicit policy binding
spec:
  parentRefs:
    - name: edge-gateway                          # NGF GatewayClass
  hostnames: ["api.example.com"]
  rules:
    - matches:
        - path: { type: PathPrefix, value: /v1/chat }
      backendRefs:
        - kind: Service
          name: trishula-engine                   # Trishula is the backend
          port: 8080
          weight: 100                             # canary ramps are ordinary weight edits
        - kind: Service
          name: chat-completions-pool            # (managed below the engine — see topology note)
          weight: 0
---
apiVersion: v1
kind: Service
metadata:
  name: trishula-engine
  annotations:
    appProtocol: kubernetes.io/h2c                # h2c to the engine
spec:
  selector: { app.kubernetes.io/name: trishula-engine }
  ports: [{ name: http2, port: 8080, appProtocol: kubernetes.io/h2c }]
```

Contract terms, each CI-tested against NGF[39][249]:

1. **Steering:** the gateway steers to `trishula-engine` as it would to any Service — weighted `backendRefs`, header matches and canary weights. Trishula never selects endpoints. (In the reference topology the engine forwards to the pool Service. Pools on the Inference Extension keep their EPP machinery downstream of the engine — §10.4.)
2. **Health:** engine readiness tracks the current bundle load state (not process liveness). Unhealthy replicas leave the Service's endpoints. The gateway's endpoint tracking removes them from rotation automatically.
3. **Failure semantics per route:** `failOpen` (engine down → the gateway routes direct to the pool via the weight-0 fallback `backendRef`) or `failClose` (drop). One vocabulary spans the path, on the EPP contract's FailOpen/FailClose[41][43].
4. **Protocols:** h2c engine ingress (`appProtocol: kubernetes.io/h2c`); gRPC framing recognized. TLS termination is gateway-owned (listener `tls.mode: Terminate`), so the engine sees plaintext (§9.7).
5. **Binding:** policy attaches via the HTTPRoute annotation `trishula.security/policy: <name>`, or via namespace-scoped `WAFPolicy.routeSelectors` — most-specific wins. `Bound`/`UnresolvedRef` Conditions in CR status mirror the Gateway API conventions.

### 10.3 The reference walkthrough (the lab every claim is proven in)

```mermaid
flowchart TB
    subgraph KIND["kind lab (CI: nightly + PR)"]
        subgraph EDGE["Gateway tier"]
            NGF["NGF Gateway 'edge-gateway'<br/>GatewayClass nginx (NGF)<br/>TLS terminate @ listener"]
        end
        subgraph WAF["Trishula"]
            OP["operator"] --> ENG1["engine replicas<br/>(readiness = bundle state)"]
            DS1["shield DaemonSet"]
        end
        subgraph AI["AI estate"]
            EPP["Endpoint Picker<br/>(GIE, ext_proc)"]
            POOL["vLLM/GIE model pool<br/>InferencePool"]
        end
    end
    C["developer: kubectl apply<br/>(WAFPolicy, APISpec, HTTPRoute)"] --> KIND
    NGF -->|"backendRef → engine svc"| ENG1
    ENG1 -->|"transparent forward"| POOL
    DS1 -.->|"ringbuf"| ENG1
    EPP -.->|"endpoint choice<br/>downstream of engine"| POOL
```

*Figure 8. The CI-proven reference: kind + NGF + Trishula (+ EPP where AI routes need it).*

The lab proves, in CI:
- NGF steering of weighted traffic to the engine
- readiness flips remove and add engine endpoints
- a `429` ban response with `Retry-After` traverses NGF unmangled
- h2c upgrades
- TLS termination leaves plaintext at the engine
- shadow vs enforce verdict parity
- uninstall leaves zero kernel residue (DX6) The kind→k3s→managed-K8s progression is the documented adoption path: the same manifests, bigger cluster.

### 10.4 Beyond the proxy hop: ext_proc (v2) and the Inference Extension

- - **ext_proc stage (a later stage, feature-gated).** Envoy-family data planes (Envoy Gateway, kgateway, Istio/agentgateway) can call out to an `ExternalProcessor`. Trishula's engine ships this server from the rc1 cut (one binary, two transports). Ext_proc-capable estates get a **no-proxy-hop** WAF. Headers and body chunks arrive as gRPC frames. The engine returns verdicts, mutations and dynamic metadata. The wire contract is fixed in §19.1. NGF is the reference for Variant A today; ext_proc estates activate the stage with the same engine.
- **Inference Extension ordering.** On EPP-enabled routes (NGF + GIE integration[39]), EPP runs as its own ext_proc stage alongside the gateway. Filter ordering (WAF before/after EPP) is per-gateway configuration, not standardized upstream. The operator emits the ordering snippet per estate. WAF-before-EPP spares EPP/queue capacity on block. EPP-before-WAF lets verdicts use the selected-endpoint class as policy input. Either order leaves `x-gateway-destination-endpoint` metadata untouched: the WAF writes its own metadata namespace, never EPP's (§19 ext_proc contract).
- **What this does not change:** steering stays gateway-owned in every variant. Trishula never selects endpoints.

### 10.5 Portability honest-delta

| Capability | NGF (reference) | Any conformant gateway | Degradation, if any |
|------------|-----------------|------------------------|---------------------|
| Steer HTTP to engine Service | ✅ core | ✅ core | none |
| h2c to engine | ✅ | ✅ common | none |
| Weighted canary/shadow ramp | ✅ | ✅ core | none |
| Readiness-gated pools | ✅ | ✅ universal | none |
| Gateway TLS termination | ✅ `Terminate` | ✅ table stakes | none |
| Weight-0 fallback `backendRef` for failOpen | ✅ | implementable on conformant impls; **verify per gateway** | failOpen may need header-based fallback instead |
| ext_proc no-hop mode | — (v2 on Envoy-family) | Envoy-family only | Variant A everywhere else |
| EPP model-pool steering | ✅ documented[39] | GIE-conformant impls | static weights elsewhere |
| Shield (eBPF) | ✅ gateway-independent | ✅ gateway-independent | none — the shield does not care who fronts the cluster |

The shield carries the portability guarantee. Even where a gateway feature is missing, the kernel-level protections (ACL, floods and bans) hold. Portability is insurance, not parity. NGF is the recommended primary.

<div class="pagebreak"></div>

## 11. Rule Engine & Detection

### 11.1 The ladder and its compiling sources

The evaluation ladder of §2.3 is compiled from four authoring surfaces through one operator:

```mermaid
flowchart TB
    subgraph AUTHORING["Authoring surfaces"]
        CRS["OWASP CRS bundles<br/>(SecLang import)"]
        CELD["CEL Rule DSL<br/>(developer-authored)"]
        SCHEMA["OpenAPI 3.1 APISpec<br/>(positive security)"]
        MLR["ML models<br/>(ONNX / async judge)"]
    end
    subgraph COMPILE["Operator compiler"]
        C1["CRS → evaluator chain (Coraza)"]
        C2["CEL → compiled program (cost-budgeted)"]
        C3["hot patterns → Vectorscan DB"]
        C4["bans/verdicts/maps → kernel map values"]
    end
    AUTHORING --> COMPILE
    COMPILE --> EVAL["Engine ladder S0–S7 (§2.3):<br/>kernel cache → matcher → CRS → CEL →<br/>schema → bots → rates/bans → ML"]
```

*Figure 9. One bundle; the ladder short-circuits on the first decisive verdict.*

### 11.2 CRS: the correctness baseline

- CRS 4.x imports as first-class `RuleSet.source` (bundle + paranoia level + per-rule exclusions)[139][141][178]. SecLang is parsed by the embedded Coraza-compatible evaluator[134][133]. CRS parity is a CI gate (§11.8), not an aspiration.
- **Why borrow CRS:** community-maintained coverage for OWASP Top-10 classes, PL1–PL4 tuning vocabulary and the exclusion ecosystem[142][171][132]. A new corpus costs years of FP tuning.[322]
- **Why CRS alone is not enough:** regex-chain cost at scale; no positive-security model; no bot/rate/ban semantics; no AI-class detection.[161][162][159] CRS gives coverage; Trishula adds speed (§11.4) and altitude (§2.3).

### 11.3 CEL as the developer-facing DSL

CEL is the choice over new DSLs, Rego and proxy-wasm. The reasons: a small and well-specified expression language[137]; Envoy/K8s familiarity (CEL authz, admission control)[157][146]; fast AST evaluation; a cost budget. It addresses a structured request view:

```
request.method, request.path, request.headers (map),
request.body.{text, json, form, bytes}, request.uri_queries,
request.client.{ip, asn, geo, reputation, ban_state},
request.auth.{verified | subject | issuer | audiences | scopes | expiry_epoch | claims},
request.ja4, request.rate_windows,
response.{status, headers, body-chunks},
tx.{score, matched_rules, flags: {smuggling_suspect, oversized_body, ...}}
```

Example developer rules:

```
// rate-shape rule (feeds the §13 ladder as a scoring input)
request.method == "POST" && path.matches("/v1/chat/*") &&
request.rate_windows["5m"].requests > 40

// body-level rule with the structured view
request.method == "POST" &&
path.matches("/v1/chat/*") &&
request.body.?json.messages.size() > 128 &&
request.client.reputation < 0.3
```

Ladder position: after the CRS short-circuit, before schema gating, for observability parity. Per-rule `action/phase/tags/severity` carries the SecLang semantics for imported-rule parity.

**The claims vocabulary (TR-198).** The view carries the `request.auth` names of the [auth/JWT verdict record](https://github.com/trishula-dev/trishula/blob/main/docs/design/auth-jwt-verdict.md). `request.auth.verified` reads bool. `request.auth.issuer` and `request.auth.subject` read string. `request.auth.audiences` and `request.auth.scopes` read list(string). `request.auth.expiry_epoch` reads int (epoch seconds). `request.auth.claims` reads map(string, dyn).

The gateway's verified identity metadata fills the names. The optional in-engine HS256/RS256 verifier bundle is the second source. The operator supplies the bundle. The engine verifies the token bytes the authorization header carries. The header never reads as a claim source. A self-asserted identity header never fills a name.

A missed or failed verification sets `request.auth.verified = false`. The missed reads resolve the empty list or map value. CEL reads the miss. No rule panics.

The gate: every allow-shaped rule carries `request.auth.verified` in its condition. So `verified = false` holds every allow path. The claims gate runs at S3, after the CRS short-circuit, before schema gating. Its deny verdict is policy-selected block (403 class). The scope comparison uses the language operators first: `"read:orders" in request.auth.scopes`. The comprehension form is `request.auth.scopes.exists(s, s in ["read:orders"])`. Rules compare `request.auth.expiry_epoch` against the engine-supplied epoch (`now`). CEL never reads a clock. Every comparison costs against the per-rule budget. An over-budget rule aborts as an error verdict. An error never reads as a clean no-match.

Example claims-gate rule:

```
// the S3 claims gate: /orders/* admits a verified
// identity carrying read:orders (the verified gate
// in the deny condition; the record's taxonomy id)
// auth:scope_insufficient (action: enforce)
path.matches("/orders/*") &&
(!request.auth.verified || !("read:orders" in request.auth.scopes))
```

### 11.4 The compiled fast path: Vectorscan matcher

The hot subset of CRS + CEL patterns compiles to a Vectorscan DB (open-source Hyperscan-family; x86/ARM/POWER[173][128]; Suricata-backed[172]). One scan covers the pattern set, block and streaming mode over reassembled bodies.[136][129] **Differential gate:** the gate shadow-evaluates matcher verdicts against the reference evaluator on 100% of traffic. Divergence demotes the pattern to reference-path-only (self-healing parity; §11.8). The memory budget is validated in §17.2 (R2b).

### 11.5 Positive security (schema) and API discovery

- `APISpec` CRs wrap OpenAPI 3.1 docs per (host, route-prefix): paths, methods, params, content types, field types, lengths, required and patterns → compiled validators.
- **Enforce mode:** unmatched path/method → block. Param type/length/pattern violations → block, with per-field telemetry. This is the tier-1 commercial feature the OSS field rarely ships (§4).
- **Learn mode:** discovery builds the spec from live traffic (endpoint extraction, JSON-schema inference with cardinality tracking) and emits CR diffs. Drift telemetry reads the live-vs-reviewed divergence.
- Response-side schema (exfiltration guard): a later slice (§20.2).

### 11.6 Bot detection & anti-automation (detail in §12)

The ladder's S5 family: JA4/JA4S fingerprints at the termination hop, header order/entropy, and per-source behavioral windows from the shield. Per-detector verdicts merge into the request score *and* the ban score.

### 11.7 Rule lifecycle (shadow-first)

```mermaid
stateDiagram-v2
    [*] --> Draft: RuleSet CR applied
    Draft --> Shadow: operator compiles + deploys (verdict-only)
    Shadow --> Enforceable: evidence gate (matches>0, FP delta<=0 over N requests)
    Shadow --> Draft: FP feedback / edits
    Enforceable --> Enforce: policy promotes (enforce: true)
    Enforce --> Draft: tuning/exclusions workflow
```

*Figure 10. Shadow-first lifecycle; promotion requires evidence, never a dry `apply`.*

`kubectl apply` → operator compile → signed bundle distribution → per-replica atomic swap (double-buffered matcher DB + evaluator chain) → CR status Conditions. The time-to-enforce target is 5 s (§17 gate).

### 11.8 CRS differential parity gate

The product's honesty mechanism runs twice:

```mermaid
flowchart LR
    subgraph CI["Continuous integration"]
        CRS["CRS regression corpus<br/>+ adversarial corpora<br/>+ recorded FP-heavy samples"]
        REF["Reference evaluator<br/>(Coraza)"]
        FAST["Vectorscan fast path"]
        CELC["Compiled CEL rules"]
        DIFF["Differential assert:<br/>verdict parity 100%"]
    end
    subgraph PROD["Production (shadow-parallel)"]
        LIVE["Live traffic (mirrored)"]
        ENG["Trishula engine"]
        INC["Incumbent WAF (during migration)"]
        TEL["Verdict telemetry diff"]
    end
    CRS --> REF
    CRS --> FAST
    CRS --> CELC
    REF --> DIFF
    FAST --> DIFF
    CELC --> DIFF
    DIFF -->|"fail = block release"| CRS
    LIVE --> ENG
    LIVE --> INC
    ENG --> TEL
    INC --> TEL
    TEL -->|"FP delta + missed-match report"| CRS
```

*Figure 11. Release-blocking in CI; evidence-generating in production.*

Rules of the gate: parity is **verdict-level** (block/log/pass + matched-rule IDs + score ladder). The corpus: upstream CRS regression tests + curated adversarial corpora + recorded production samples[177][165]. A fast-path pattern that disagrees with the reference evaluator is **demoted automatically**. Exclusions are versioned and shadow-tested like any rule change.

The corpus carries a third class on top: the **illegal-request rows**. The h1 framing-ambiguity rows ([TR-44](https://github.com/trishula-dev/trishula/blob/main/docs/design/protocol-conformance-verdict.md), TR-199) pin the parse-path reject cells. The cell: the `block` verdict with the parse-layer rule id. A CRS-only walk on the same shapes matches no attack rule. The gate README records the measured delta.

<div class="pagebreak"></div>

## 12. Bot Defense & Anti-Automation

Bots are the workload most HTTP security products still treat as a signature problem. Trishula treats bot detection as **evidence accumulation**. Three independent detector families contribute to one per-source bot score. The score feeds both inline decisions and the ban engine (§13).

### 12.1 Detector families

| Family | Signal | Mechanism | Cost kernel/userspace |
|--------|--------|-----------|----------------------|
| **TLS fingerprinting** | JA4/JA4S of the client handshake[197][F-ja4] | computed at the termination hop (gateway) and passed as metadata, or engine-computed when the engine terminates; matched against known-tooling DB | userspace, µs-class |
| **Header-plane fingerprints** | header order, casing, value entropy, HTTP-version quirks | ordered-hash comparison against browser/tooling profiles; detects curl/python/bot-framework masquerades | userspace, µs-class |
| **Behavioral** | request pacing, path-traversal graphs, session continuity, auth-failure ratios, endpoint-uniqueness | per-source sliding windows (§13.2 counters) + session-scoped aggregates | kernel counters → userspace scoring |

Each detector emits `(detector_id, confidence, evidence_ref)` — never a bare boolean. The merge rule is configurable per `WAFPolicy`. A consensus of ≥2 families triggers action. A single-detector match logs and scores.

### 12.2 Verdict integration

```mermaid
flowchart LR
    subgraph DET["Detector families"]
        JA["JA4/JA4S<br/>TLS fingerprint"] --> MG
        HD["header plane<br/>order/entropy"] --> MG
        BH["behavioral windows<br/>(kernel counters)"] --> MG
    end
    MG["per-source bot score<br/>(merge: consensus policy)"] -->|"inline tier"| LADDER["request ladder<br/>S5 verdict"]
    MG -->|"session tier"| BAN["ban engine<br/>(§13 score)"]
    LADDER -->|"403/429 events"| BAN
    BAN -->|"repeat pattern"| KT["kernel ban_table"]
```

*Figure 12. Bot evidence flows two ways: inline per-request, and into the temporal score that causes bans.*

- **Known-good bots** are an allowlist CR (`BotPolicy.knownGood`): documented crawlers, gateway health checkers and monitoring agents. Reverse-DNS validation runs on the termination-hop identity. A misclassified-good bot is a tuning case, not a detection failure.
- **Challenges:** the `challenge` verdict action carries the evidence-of-work mechanism. The mechanism: evidence-of-work via a signed redirect token. No third-party CAPTCHA sits in the default path. A pluggable interface serves estates that run one. TR-197 ships the token: the engine answers a challenge verdict with `429` + `Location: /__trishula/challenge?token=...` (HMAC-SHA256, 10-minute TTL, one-shot replay window; `-challenge-key` configures the key). Without a key the verdict refuses deterministically (`403`, no redirect). The redirect hop issues the evidence-of-work probe: a signed problem (a salt, a 16-bit difficulty), and the solve consumes both tokens once and mints the pass grant (a short-lived cookie bound to the original path). The pass-granted request forwards; the missing or failed proof bounces (`403`) and the bot stays on the wall.
- **Credential-stuffing posture:** auth-endpoint failure ratios + JA4 heterogeneity + velocity → high ban scores. The posture pairs with per-identity (not just per-IP) rate keys where JWT identity exists (§13.2).
- **UDP/QUIC ban path (TR-203 L1, issues #242/#264):** one live ban row drops the UDP flows at [both kernel hooks](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory). The row stays live while its `until_ts` runs ahead of the kernel clock. Expiry re-opens the walk ([the ban algorithm](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified)). The stale row waits for the LRU's lazy eviction. The counters count and drop; they never issue a ban ([the rate accounting](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#95-kernel-side-rate-accounting-feed-13)).

### 12.3 Honest limits

- TLS fingerprints are forgeable by a sufficiently motivated attacker (JA4 is a *cost raiser*, not identity);[F-ja4] header fingerprints are similar. The design assumes adversaries adapt. Behavioral windows (§13) are the harder-to-forge altitude: the kernel observes them, not the client.
- Fingerprint DBs decay (library versions change). The known-tooling matching set ships as a digest-pinned feed CR on the §16.6 upgrade cadence, with nothing hardcoded.

<div class="pagebreak"></div>

## 13. Rate Limiting, DoS Response & Temporary Bans

**This section is the product's named differentiator:** a fail2ban-for-HTTP algorithm. The fail2ban temporal-ban UX is re-specified for HTTP[147] and recomputed on the wire. It runs in the kernel and surfaces as first-class OTel events. Rate limiting *limits*. Bans *remove*. Trishula ships both as one scored pipeline.

### 13.1 Why temporary bans, and why kernel enforcement

A rate limit answers "too fast, slow down". A temporary ban answers "the source is an actor: leave for N minutes". Every fail2ban operator knows the operational value. Thresholds and windows are legible. Bans are temporary and auditable. Repeat abuse escalates without permanent blocklist maintenance. But fail2ban parses logs — a wire-level problem answered at tap altitude, with filesystem state and no per-route policy.[147] Trishula moves compute to the engine (full HTTP view) and enforcement to the shield (NIC owner, line rate). State is a kernel map + a userspace ledger. Every step is a CRD knob and an OTel event.

### 13.2 The rate algorithms (per-route, CRD-selected)

| Algorithm | Best for | Semantics | Notes |
|-----------|----------|-----------|-------|
| **Token bucket** | steady-state per-route budgets | refill rate r, burst b; reject when empty | the default for API quotas; matches NGINX/Envoy semantics[149][F-ngxrl] |
| **Sliding window** | burst-sensitive endpoints | exact windowed count over k samples; no boundary spike | anti-brute-force on auth endpoints |
| **EWMA rate** | behavioral DoS signals | exponentially weighted arrival rate per source | kernel-side `rate_windows` already produce these (§9.5); cheap and smooth |
| **Score ladder** | the ban decision itself | weighted event scores in a sliding findtime window | §13.3 — the fail2ban translation |

Rate keys are CRD-composable: source IP (default), IP+route-class, JWT `sub`/`client_id` when identity exists, or the JA4 cluster. Keys compose: a route may limit per-IP *and* per-identity simultaneously.

### 13.3 The ban algorithm: `ScoredWindowBan v1` (specified)

Named, versioned and pinned by this document. Implementations must reproduce it from this spec alone; a conformance test does exactly that.

```
State per source key s:
  events[s]  : sliding window of (timestamp, weight)   # decayed evidence
  state[s]   : ACTIVE_BAN(until, tier, reason_codes) | CLEAR
  recidivism[s] : count of prior bans (for backoff)

Constants (BanPolicy CR defaults ⇢ fail2ban analog):
  findtime      W   = 10m        ⇢ findtime   (evidence window)
  threshold     T   = 10         ⇢ maxretry   (score, not raw count)
  bantime       B   = 10m        ⇢ bantime    (base duration)
  backoff       κ   = 2          ⇢ recidive jail (exponential repeat multiplier)
  max_bantime   Bmax = 24h       (human-scale cap; permanence is a decision, not an accident)

Scoring (weights from BanPolicy, defaults):
  CRS critical match            +5     CRS warning match        +2
  bot consensus verdict         +4     single-detector bot hit  +1
  rate-window breach            +3     schema violation         +2
  auth failure (401/403)        +2     kernel EWMA burst flag   +3
  score decay: exponential, half-life 20% of W (staleness by design)

Decision loop (engine, per request + periodic sweeper):
  1. score[s] = Σ w_i · exp(−λ·(t_now − t_i))  over events in W      # λ from half-life
  2. if state ACTIVE_BAN and t_now < until: enforcement continues (§13.4); no re-scoring
  3. if score[s] ≥ T: ban → state = ACTIVE_BAN(
         until  = t_now + min(B · κ^recidivism[s], Bmax),
         tier   = scored-window, reason_codes = weight contributors)
     recidivism[s] += 1; emit ban event (§13.5)
  4. unban: automatic at until; evidenced early-release only via §13.6 workflow

Prefix escalation (opt-in, default off — collateral risk gate):
  if ≥ N distinct keys in one /24 (IPv4) or /48 (IPv6) banned within W:
    issue prefix ban at /24 or /48 with a stricter tier + shorter bantime
    (the bansubnet idea[147], gated behind a threshold that makes accidents rare)
```

- **Shadow-first:** `BanPolicy.mode: shadow` computes and emits ban verdicts (metrics + logs) *without* enforcement. Promotion requires the same evidence gate as rules (§11.7). A new route reaches its thresholds by evidence this way — no folklore tuning.
- **Kernel enforcement:** the engine writes ACTIVE_BAN keys into the `ban_table` map (§9.3) with expiry. XDP/TC drops (or tarpits) without consulting userspace. Ban writes use the always-sampled high-priority ring class (§9.4).
- **What the kernel never does:** compute scores. The kernel is decision-free (verifier-bounded, audit-simple). It applies the verdicts it is given (§9.5).

### 13.4 Enforcement actions by tier

| Tier | Trigger | Action | Client sees |
|------|---------|--------|-------------|
| L0 observe | first breaches | log + score only | normal response |
| L1 rate | rate-window breach | throttle | `429` + `Retry-After`[F-rfc9110] |
| L2 ban | score ≥ T | temporary drop at kernel + `429` mirror at app layer | connection drop / `429` + `Retry-After` |
| L3 tarpit | flood-class (kernel EWMA) | kernel tarpit/drop at XDP | connection timeout |
| L4 prefix | §13.3 escalation | prefix-level XDP drop | drop |

`Retry-After` is always present on any 429 Trishula emits. This is a deliberate developer-experience signature (DX5). The rate-limited client sees when to retry, from the component that rate-limited it.

### 13.5 Observability of bans (first-class)

- `trishula_ban_active{tier,key_class}` gauge; `trishula_ban_total{tier,reason,action}` counter; `trishula_ban_score` histogram per key class.
- Every ban decision emits an **OTLP log record** (§15): key, score trajectory (the contributing events with weights), trigger rule refs, until and tier. The analyst reads *why* without replaying anything.
- Ban table state is exportable (`trishulactl ban list --output json`) — CRD-adjacent debuggability, no console.

### 13.6 Unban and override

- Automatic expiry (map TTL + ledger sweep).
- Analyst release: `trishulactl ban release --key <k> --reason <txt>` — audited, and it emits an OTel event referencing the operator identity (K8s RBAC governs access to release).
- Developer release (the DX1 path): a `BanRelease` CR, applied by the app team for their own route class during a false-positive incident. The scope is namespaced-RBAC. The release event links to the ban event's evidence in the audit log.
- Unban evidence (post-release behavior) is tracked: a released key re-banned within B re-enters recidivism with κ raised. The algorithm separates "CI from a datacenter IP" from "a retrying botnet node".

### 13.7 DoS response posture (who does what)

```mermaid
flowchart TB
    subgraph KERNEL_DO["Kernel plane (no parsing, no scoring)"]
        XDP2["XDP: LPM ACL, SYN/UDP flood tarpits,<br/>ban_table + prefix drops, EWMA counters"]
    end
    subgraph ENGINE_DO["Engine plane (full HTTP view)"]
        RL["per-route rate algorithms<br/>(token bucket / sliding window)"]
        BANENG["ScoredWindowBan v1<br/>scores, bans, recidivism"]
        BDOS["behavioral DoS detectors<br/>(slowloris math, h2 rapid-reset shape)"]
    end
    XDP2 -->|"counters + burst flags<br/>(ring, high-priority)"| BANENG
    RL -->|"breach events (weights)"| BANENG
    BDOS --> BANENG
    BANENG -->|"ban keys + expiry"| KERNEL_DO
```

*Figure 13. Division of labor: kernel counts and drops; the engine scores and decides; bans feed back kernel-ward.*

- **L3/L4 floods:** shield XDP tarpits/drops (§9.2), independent of any policy. This layer is fail-open by default (a shield bug must never take the path down; R7 discipline).
- **Slowloris / connection starvation:** kernel `flow_stats` (§9.3) feed the engine's behavioral detector; the response is L2/L3 bans. A per-request WAF cannot win this fight; a flow-keyed kernel counter can. The shield runner (`cmd/shield`, TR-195) runs the loop automatically: it reads the pinned `flow_stats` map, forms the detector cues with the measured signature (`segs`, `bytes/seg`, `span`), ingests them into the scored ban path, and the enforcer publishes the kernel row. The evidence record carries the signature verbatim (`osig`): the map read, the evidence row and the kernel drop state the same measured facts. The verdict pipeline emits each would-ban as a `trishula.ban` record, and the `verdict.dos.sig` attribute carries the signature when the verdict holds one. The engine host emits one verdict signal set per consult decision; a ban decision carries `verdict.dos.sig` with class `manual-rule` and the request path.
- **Manual bans:** operators can ban directly with a CEL rule (`action: ban` in a rule pack); the engine emits the would-ban record on the same enforcer path (TR-195, issue #237).
- **h2 rapid-reset shape:** the engine parser reads stream-reset ratios per connection; it flags `tx.flags.rapid_reset_suspect`, scores and (on confirmation) bans.
- **Application-layer request floods:** §13.2 algorithms + ban ladder.
- **Oversized/malformed:** parser admission caps (§17.2 R-DoS) — 413/400 fast, with no resource asymmetry.
- **What Trishula does not do:** BGP-grade volumetric defense belongs to the upstream network. Trishula makes the *first node in the cluster* a bad target, not the last hop on the public internet.

<div class="pagebreak"></div>

## 14. ML & Adaptive Detection

### 14.1 Scenario catalog

| # | Scenario | Signals | Model class | Band | Phase |
|---|----------|---------|-------------|------|-------|
| S1 | Known-attack classifier | decoded-payload features, CRS match context | supervised tree/linear (XGBoost-class) | inline, µs | P1 |
| S2 | Zero-day anomaly | request/session feature vector (lengths, entropy, char-class, param counts, rate shapes) | Isolation Forest / LOF | inline, sub-ms | P1 |
| S3 | Bot / ATO / stuffing | JA4 + header fingerprints, behavioral windows, auth ratios, endpoint-uniqueness | per-detector voting ensemble, session-level | session-window | P1+ |
| S4 | Prompt-injection / jailbreak semantics | token sequences, instruction patterns | small classifier cascade first; LLM judge async | cascade + async | P1+ |
| S5 | Exfiltration on responses | response-entity volumes vs schema, entropy spikes, PII patterns | rules + S1/S2 on response view | response path | P2 |
| S6 | API behavioral drift | per-endpoint verdict/feature distributions | drift monitors (PSI-class) on verdict streams | offline + canary | P1 |

### 14.2 The hand-off contract: ML never reads packets

The binding design rule: **ML reads structured feature views derived from engine + eBPF events** — never raw wire data.

```mermaid
flowchart LR
    subgraph SRC["Event sources"]
        FE["shield flow_events<br/>(ringbuf: counters, flags)"]
        PV["engine parsed request view"]
    end
    subgraph FEAT["Feature extraction"]
        EX["Feature extractor<br/>(fixpoint structs)"]
        FV["FeatureView<br/>(canonical, versioned)"]
    end
    subgraph MLT["ML tiers"]
        T1["T1: ONNX inline<br/>(S1+S2, µs–ms)"]
        T2["T2: verdict cache<br/>(sig-keyed, TTL, model-tagged)"]
        T3["T3: escalation pod<br/>(Triton, heavier models)"]
        T4["T4: LLM judge<br/>(async, suspicious-only)"]
    end
    FE --> EX
    PV --> EX
    EX --> FV --> T1 --> T2
    T1 -.->|"score ≥ escalation τ"| T3
    T3 --> T2
    T3 -.->|"semantic question"| T4
    T2 -->|"writes back"| KERNELM["kernel maps<br/>(verdict_cache / ban_table)"]
```

*Figure 14. Feature views are versioned artifacts; verdicts backfill kernel caches — including ban tables, closing the loop with §13.*

1. **FeatureView v1 (stable, version-tagged):** a per-request vector. The fields:
method/path-class one-hots and body-size buckets; entropy and char-class stats; param counts and type
hashes; decoded-layer indicators and `src_rep` fields; fingerprint fields (JA4 hash, header-order
simhash); session-window aggregates and rate-window values.
eBPF contributes cheap counters (§9.5); the parser contributes payload features. Precedent: a hybrid eBPF/ML IDS. Kernel-extracted flow features travel via ringbuf to a userspace ensemble. Verdicts write back to the kernel maps. End-to-end median: 1.4 ms on one core.[222]
2. **Inline tier (T1) budget:** ONNX Runtime CPU; tree/linear models on tabular features are µs-class.[215][216] BERT-class transformers are out of the inline budget (BERT-base CPU p50 ≈ 42 ms)[228]. The design instead cascades — cheap-first, then escalate (literature: near-transformer accuracy at ~0.1 ms effective average[216]).
3. **Escalation tier (T3):** a Triton pod[242][244] for suspicious-band traffic only. Synchronous only when the route budget allows; otherwise async with verdict-cache backfill. GPU sharing rides MIG slices for SLO isolation where GPUs exist.[224][225]
4. **LLM judge (T4):** always async and suspicious-only, with verdicts cached (TTL 24 h default). The judge model and prompt pin as supply-chain artifacts. Heterogeneous judges improve robustness; the judge is itself an attack surface (surrogate-transfer and poisoning results[217][218][219]). Oracle access is rate-limited (§13), and verdicts are never LLM-only.
5. **Verdict cache (T2):** a userspace LRU keyed on the normalized request signature, TTL + model-version tag. High-confidence block verdicts **and ban scores** write back to kernel maps → repeat enforcement at line rate (§13.3 loop closure).
6. **Learning lifecycle (per asset):** `learn` → `shadow` → `enforce-high-confidence` → `enforce-full`. Promotion gates: sample volume, convergence and a shadow FP at or under budget. Precedent: open-appsec's lifecycle, minus its central-plane coupling[239][201]. SafeLine's audit/balance/strict modes[202] inform the knob surface.
7. **Drift as security telemetry:** prediction-drift monitoring watches per-endpoint verdict rates. The watch doubles as an **evasion canary** (a rise in suspicious-but-allowed is often probing). PSI-class alerting uses rolling reference windows. Retraining gates off confirmed drift, not raw alerts.[243]

### 14.3 Evasion posture (documented, evidenced)

- Threat model: mutation-based evasion, surrogate-model adversarial optimization, judge manipulation.[230][234][218][219]
- Mitigations:
  - probe rate-limits + shadow-first (they limit the oracle budget on the expensive stages)
  - perturbability-scored feature selection (favor hard-to-perturb flow/behavioral stats over user-controlled strings)
  - heterogeneous ensembles
  - verdict-cache TTLs bound probe reuse
  - every ML verdict carries an explanation for the analyst loop
- Honest limit: no ML WAF is evasion-proof. The goal is a higher attacker cost, not purity.[211]

<div class="pagebreak"></div>

## 15. OpenTelemetry Observability

**OTel is a product surface, not an afterthought:** traces, metrics and **OTLP logs as first-class signals**. All signals correlate, and all export to the backend the team already runs. The WAF verdict is a trace event on the request's span. The developer who owns the API finds security answers next to the latency answers (D4 thesis, mechanized).

### 15.1 The three signals, as contracts

| Signal | What Trishula emits | Key correlation |
|--------|--------------------|-----------------|
| **Traces** | one server span per request at the engine (stages: parse → ladder S0–S7 → verdict → forward); shield events attach as span links/attributes; upstream forwarded with propagation headers preserved | `trace_id` = the request's identity end-to-end (gateway sets it; engine never strips) |
| **Metrics** | per-rule match counters, per-phase latency histograms, ring depth/drops, cache hit rates, ban gauges/counters (§13.5), ML tier latencies + verdict distributions, schema-drift counters, exclusion hit counts | exemplars carry `trace_id` → jump from dashboard to trace |
| **Logs (OTLP)** | structured verdict log records: verdict, rule IDs, plain-language reason (DX5), score ladder snapshot, ban evidence blocks (§13.5), body samples only under `debugBodies` CRD flag with redaction always on | every record carries `trace_id` + `rule_id`; the ban record carries the full score trajectory |

### 15.2 The verdict record (log-body schema, versioned)

```json
{
  "schema": "trishula.verdict.v1",
  "trace_id": "…", "span_id": "…",
  "route": {"host": "api.example.com", "path": "/v1/chat", "policy": "chat-completions"},
  "shield": {"stages": 127},
  "client": {"ip": "…", "ja4": "…", "asn": 0, "reputation": 0.42, "rate_windows": {"5m": 41}},
  "ladder": [
    {"stage": "kernel", "matched": [], "us": 1},
    {"stage": "matcher", "matched": ["920480"], "us": 12},
    {"stage": "crs", "matched": ["942100"], "score_delta": 5, "us": 210},
    {"stage": "bots", "detectors": {"header_order": 0.8}, "consensus": false},
    {"stage": "rate_ban", "windows": {"5m": {"requests": 41, "limit": 30}}, "breach": true}
  ],
  "verdict": {"action": "ban", "tier": "scored-window",
              "reason": "rate breach + CRS critical within findtime",
              "until": "2026-10-01T12:40:00Z", "ban_recidivism": 0,
              "doc_ref": "docs/academy/module4-rates.md#scoredwindowban"},
  "evidence": {"body_sample": null, "note": "debugBodies disabled"}
}
```

`doc_ref` is the teach-the-web hook (§7.2): every machine verdict points at the human explanation of the mechanism that fired it.

The stage-stamp vocabulary follows the verdict record at [docs/design/stage-stamps-verdict.md](design/stage-stamps-verdict.md).

**The stage-stamp record surface (TR-194, 2026-10-25).** The record evolves
additively; the schema stays `trishula.verdict.v1`:

- `ladder` rows run in walk order, one row per run stage. The row shape
  stays `{stage, matched, us}`. The `stage` tokens use the canonical
  name set: `kernel`, `matcher`, `crs`, `cel`, `schema`, `bots`,
  `rate_ban`, `ml`. The design record holds the taxonomy (the link
  above). A skipped stage carries no row. A row never claims a skipped
  stage.
- The optional root object `shield` carries the kernel-plane consult
  bitmap as one integer: `"shield": {"stages": 127}`. Bits 0–6 name the
  kernel-plane consults (the record's XDP and TC bit tables). A request
  with no correlated shield event carries no `shield` field. A zero
  bitmap reads 0 on a present event.
- The verdict span carries one link per correlated shield event. The
  link attributes carry the event fields (timestamps, family, ports,
  TCP flags, payload length, path hint, the stages integer). A link
  carries a context + attributes, never a span.

### 15.3 Kernel-plane counters (shield)

The shield exports this counter set:
- XDP drop/pass/tarpit, per map and reason class
- ring depth + drops
- per-prefix rate EWMAs
- ban-table occupancy/expiries Export runs on a fixed tick, OTel-native. An xdpcap-compatible capture hook ships from day one. XDP-dropped packets are invisible to tcpdump; forensics needs a sanctioned capture path[66].

### 15.4 Dashboards & redaction

- Grafana pack ships in-repo per route class: verdict mix, altitude hit-rates (kernel/matcher/evaluator/ML), FP-rate deltas, ring health, ban ledger trends, ML latencies.
- **Redaction is structural:** the pipeline drops header values carrying `authorization`/`cookie`/token-shaped strings at emission. Body bytes never leave the pod unless `debugBodies: true` is set per policy *and* a purpose annotation is present. OTel exporters get the same treatment as logs (§18.3).
- Every record's schema is versioned (`trishula.verdict.v1`). Backends pin and migrate explicitly; scraping and guessing are out.

<div class="pagebreak"></div>

## 16. Kubernetes Deployment Model & Operations

### 16.1 Workloads

| Deployable | Kind | Nodes | Privileges | Notes |
|------------|------|-------|------------|-------|
| `trishula-shield` | DaemonSet (hostNetwork) | every traffic-fronting node | privileged (BPF, netlink, BPFFS mount) | loads XDP+TC via cilium/ebpf; pins maps on host BPFFS |
| `trishula-engine` | Deployment + Service (cluster-internal) | engine nodes (label-selected, shield-co-located) | none beyond NET_BIND_SERVICE | the steered WAF backend; HPA on p99-latency + ring-depth |
| `trishula-operator` | Deployment | control-plane-ish | CRD watch, bundle distribution | compiler + rollout + status |
| escalation inference (T3) | Deployment (Triton) | GPU/MIG pool or CPU | — | only S3/S4 escalation tiers |
| telemetry | OTel Collector (existing estate) | — | — | Trishula exports OTLP traces/metrics/**logs**; no new stack |

### 16.2 CRD set (v1alpha1)

- **`WAFPolicy`** (namespaced): binds rule bundles + modes + failure semantics to route classes (HTTPRoute annotation or `routeSelectors`).
- **`APISpec`** (namespaced): OpenAPI 3.1 positive-security doc + learn/enforce/report mode.
- **`RuleSet`** (namespaced): CRS bundle refs (version, paranoia, exclusions), CEL custom rules, compiled-pattern subsets.
- **`BanPolicy`** (namespaced): §13 constants (findtime/threshold/bantime/k/max_bantime), weight table, rate-algorithm selection per route class, mode (shadow/enforce), prefix-escalation gate.
- **`MLModel`** (namespaced): digest-pinned model refs, tier, mode, thresholds.
- Status model mirrors Gateway API conventions: `Accepted` / `Programmed` / `ResolvedRefs` Conditions per CR.

### 16.3 Scheduling and resource shapes

- **Shield:** one pinned core per NIC RX queue in flood-heavy deployments. The measured envelopes: XDP drop ≈10.1 Mpps/core (Cloudflare). The FAST'18 paper records 24 Mpps/core and 41.6 ns/packet. AF_XDP zero-copy reaches 21.5 Mpps on i40e[60][75][72]. CPU-manager static policy applies. No hugepages required. Memory ≈ 256Mi base + 16Mi ring.
- **Engine:** 4 vCPU / 4Gi baseline replica (§17 targets). The HPA signal is p99 inspect-latency + ring depth. Topology-spread is required. nodeAffinity sits on `trishula.shield/ready=true`, plus a BPFFS hostPath for pinned-map access (§9.3).
- **Multitenancy:** per-namespace CRDs and per-tenant compiled bundles. Tenants demanding isolation get route-class-partitioned replicas (R8).

### 16.4 Lifecycle of Trishula in a cluster

| Stage | What happens | Owner |
|-------|--------------|-------|
| **Day-0 install** | Helm/manifests: operator first (CRDs valid), shield DaemonSet second (maps pinned, node labels `trishula.shield/ready=true`), engine Deployment third. Preflight: kernel ≥5.8 + BTF on shield nodes, BPFFS mount, native-XDP NIC modes. Lab first: the kind/NGF walkthrough (§10.3) is the documented install proof | platform |
| **Day-1 attach** | `WAFPolicy`/`APISpec`/`BanPolicy` CRs applied; routes bound; shadow baseline; CRS differential first-run | security + platform |
| **Day-2 steady state** | policy changes via CRD (shadow-first), feed refreshes on cadence (§16.6), HPA handles load, on-call follows §16.7 | on-call |
| **Drain/pause** | per-route `bypass: true` in WAFPolicy (engine forwards without inspection) or weight-shift at the gateway — maintenance without topology change | on-call |
| **Uninstall** | detach routes → engine down → shield down (per-hook detach) → operator deletes BPFFS subtree `/sys/fs/bpf/trishula/` → CRDs removed last. Zero kernel residue: `bpftool`-verified cleanliness job (DX6) | platform |

### 16.5 Versioning, upgrades, rollback

- **Independent semver lines:** operator, shield, engine, bundles. Skew tolerance: N and N−1. Bundles stay forward-compatible for one engine minor; beyond that, the `BundleIncompatible` Condition fires.
- **Kernel compatibility is a shield-release property:** CI verifies the kernel range declared per release. Out-of-range nodes take generic-XDP/TC degraded mode plus a loud Condition.
- **Upgrade order:** the operator goes first (no-ops on old CRs). The shield rolls via an atomic per-hook
  swap; a verifier failure keeps the old shield enforcing and marks the node degraded. The engine bundle
  double-buffers (drain→swap→rejoin — ordinary backend churn from the gateway's view). The reference
  topology turns NGF's endpoint tracking into canary infrastructure at no extra cost.
- **Rollback = a CRD-recorded re-pin of the previous bundle hash, with no hand edits.**
- **CRD evolution:** conversion webhooks; two-minor deprecation windows; CRD diff in release notes.
- **CRS baseline:** the engine pins the CRS 4.25.x LTS baseline. `RuleSet` CRs override it. Baseline bumps travel the same shadow gate as any rule change.
- **Release names follow the calendar rc ladder:** each planned cut of the train carries a staged rc name — 2026.01-rc1, then 2026.01-rc2, then 2026.01-rc3. The bare 2026.01 name is the GA name. A material re-cut adds a third number (2026.01.N). Labels and board vocabulary carry the same names. Scheme record: [docs/adr/0003-release-naming.md](adr/0003-release-naming.md).

### 16.6 Signature and intel feed upgrades

- **Feeds are CRs, not hidden pipeline steps.** The digest-pinned set:
  `RuleSet` (CRS + CEL); `ThreatIntel` (IP reputation/JA4 lists feeding `src_rep`);
  bot-fingerprint DBs (§12.3); `MLModel` artifacts. The operator resolves → compiles → stages via the same shadow ladder.
- **Cadence:** CRS upstream LTS quarterly point-releases → auto-PR into the fleet's RuleSet repo (the PR *is* the review). CEL customs are human PR-gated. Intel feeds take daily/weekly digest bumps without a shadow gate (additive map entries, reversible by map replace).
- **Emergency out-of-band:** a critical CVE drop uses the same CR path, with the evidence gate bypassed by `emergency: true`. The run is audited, time-boxed at 72 h, and auto-reverts absent analyst sign-off. The `PolicyEmergencyActive` alert fires.
- **FP hygiene:** verdict telemetry → exclusion workflow. Exclusion CRs are shadow-tested too.

### 16.7 Day-2 runbook

**SLOs (product-owned):** inspection p99 ≤ 1.5 ms (the §17 gate, exported continuously). Differential parity = 100%. Availability = healthy engine endpoints per route (99.9%, inline-enforced).

| Alert | Meaning | First response |
|-------|---------|----------------|
| `EngineInspectP99High` | p99 over budget 5 min | HPA events → ring depth → body-size mix → scale or shadow-bypass heavy route |
| `RingDepthHigh` / `RingDropped` | shield ring near-full | enrichment degradation, not verdict loss (§9.4): check co-location, scale node engines, hunt event storms |
| `BundleFleetDrift` | replicas with differing bundle hashes | pin rolling state; stuck replica → drain, force swap, verify parity counters resume |
| `FpRateAboveBudget` | shadow FP over budget | freeze promotion gates; open tuning-queue item |
| `BanRateAboveBudget` | ban rate anomalous (§13.5) | likely legate FP or an attack: inspect ban OTel evidence blocks before touching thresholds |
| `MlVerdictLatencyHigh` | ONNX tier over 1 ms | auto-degrade to async (built-in); investigate drift; MLModel → `mode: shadow` |
| `DriftCanary` | verdict-distribution shift (§14.2) | likely probing/schema drift → top changed endpoints → analyst review |
| `ShieldNodeDegraded` | verifier/load failure on a node | node's old shield keeps enforcing; schedule fix; never mass-restart shields |
| `PolicyEmergencyActive` | emergency-gate bypass active | analyst sign-off or 72 h auto-revert |

**Capacity:** engines scale with request rate × body depth. The shield is NIC-class. The `trishulactl capacity-plan --traffic-profile` dry-run ships in-repo.

**Backup/DR:** policies, rules and specs live in etcd + GitOps. Reapply rebuilds. Engines and shields stay stateless beyond the pinned maps. Cluster-loss recovery is a GitOps redeploy in the §16.4 order. CI ships a "rebuild-from-CRs" test: the last-enforced state is reachable from the CRs alone.

<div class="pagebreak"></div>

## 17. Performance Targets & Benchmark Plan

### 17.1 Budgets by stage

| Stage | Budget (p99, per request) | Enforced by |
|-------|--------------------------|-------------|
| XDP shield (ACL/flood/cache/ban-hit path) | ≤ 10 µs | shield DaemonSet, node NIC |
| TC classifier + ringbuf emit | ≤ 20 µs | shield DaemonSet |
| Engine parse + deep inspect (CRS+CEL+schema, 8KB body) | ≤ 600 µs | engine |
| Engine parse + deep inspect (64KB JSON body) | ≤ 1.2 ms | engine |
| ML local scorer (in-band, parallel with rules) | ≤ 1 ms | engine ML tier |
| Total inline hop added vs direct (8KB, full CRS) | ≤ 1.5 ms p99 / ≤ 300 µs p50 | end-to-end gate |
| Kernel-cached verdict/ban short-circuit | ≈ 1 µs kernel-side; ≤ 100 µs with context fetch | shield |
| Throughput per engine replica (4 vCPU, CRS+schema) | ≥ 10k req/s | load gate |

The kernel-side numbers are literature-based envelopes, not vendor claims. The sources: Cloudflare's 10 Mpps/core drop; FAST'18's 24 Mpps/core; AF_XDP 21.5 Mpps[60][75][72]. The userspace budgets are **PoC-validation targets pending a measurement**, gated by the benchmark plan. §6.4 labels them targets until a measurement lands.

### 17.2 Benchmark plan

The harness lives in-repo (`bench/`). wrk2 (closed-loop) covers latency distributions; h2load covers HTTP/2; vegeta covers burst shapes; flood scripts cover shield Mpps.

1. **Baseline** — direct-to-pool via NGF (no WAF): p50/p99, throughput, churn.
2. **Inline idle** — Trishula in path, mostly-passing traffic: isolates proxy+parse cost.
3. **Inline steady state** — CRS PL2 + schema enforce + CEL set at realistic mix.
4. **Short-circuit economics** — verdicts resolved per altitude (kernel cache, matcher, evaluator, ML) plus the cumulative cost curve; the result validates the two-plane principle.
5. **Ban-ladder effects** — ScoredWindowBan under mixed traffic. The measures: score-computation cost; the ban-hit path at XDP (target: indistinguishable from a plain cache hit); unban churn.
6. **Shield flood** — SYN/UDP floods at a test NIC: drop Mpps/core and legit-traffic preservation ratio.
7. **Body-size ladder** — 1KB→1MB through CRS PL2: throughput knee, reassembly windows, 413 thresholds and the smuggling corpus.
8. **ML ladder** — ONNX scorer batch/latency curve; degrade-to-async under backpressure (never queue the request).
9. **Hot reload** — RuleSet apply → time-to-active per replica; verdict integrity holds across the reload.

CI gates: a p99 regression over 10% fails CI. The CRS differential suite (§11.8) runs on every bpf/engine commit. Flood scenarios run nightly on bare-metal runners.

<div class="pagebreak"></div>

## 18. Threat Model of Trishula Itself

This is security infrastructure; its own compromise is an escalation path. The model is STRIDE-flavored and focused on what is specific to this design.

### 18.1 Assets and trust boundaries

- **Assets:** rule bundles, kernel map contents (verdict/ban/reputation caches), ring-buffer stream, ML models (FeatureView, weights, judge prompts), CRD state, body samples in debug logs, **ban ledger evidence**.
- **Boundaries:** kernel↔userspace (ringbuf, pinned maps — any pod with BPFFS hostPath), network front (gateway→engine hop), upstream (engine→pools), control plane (CRD apply → operator → bundles), ML supply chain.

### 18.2 Threats and treatments

| Threat | Vector | Treatment |
|--------|--------|-----------|
| **Parser-differential bypass** | smuggling-shaped requests the Trishula parser normalizes differently than upstream pools (TE/CL conflicts, obs-fold, Unicode/base64 layers)[162] | strict RFC 9112 normalization, reject-on-ambiguity; smuggling flags as `tx.flags`; differential corpus includes smuggling shapes (§11.8) |
| **Shield blind spot as bypass** | abuse timed to shield reload windows or non-shielded nodes | atomic per-hook program replace; shield-ready gating of node labels; shield-down is a Condition + metric |
| **BPFFS mount abuse** | privileged pod reads/writes pinned maps (verdict-cache or **ban-table** poisoning) | pin only under trishula-owned dir, map write perms restricted to shield UID; map writes treated as operator-plane API with audit; alert on foreign map writers |
| **Ban-table weaponization** | attacker farms evidence against a victim key (shared NAT/CGNAT egress) to ban legitimate users | prefix-escalation off by default (§13.3); per-identity keys where JWT exists; `BanRelease` CR (§13.6) gives named victims a namespaced-RBAC unban path; ban evidence records name contributing rule refs |
| **Ring flood / enrichment forgery** | malicious local workload farms ring events to starve engines or inject fake flow metadata | bounded structs (no free text beyond bounded fields); engine-side consumer budgets per source; flow metadata advisory — decisive verdicts come from payload the engine parsed itself |
| **CRD/registry supply chain** | malicious RuleSet CR (ReDoS), poisoned ML model, tampered CRS bundle | CRD RBAC + admission policy per namespace; bundles digest-pinned + operator-signed; MLModel refs digest-pinned; CRS bundles from pinned upstream tags with recorded hashes |
| **Judge/model poisoning & oracle abuse** | adversary probes ML tiers to craft evasions or poison learning | probe rate-limits (§13), shadow-only learning inputs gated by analyst promotion, canonicalized judge inputs, heterogeneous judges, verdict-cache TTLs bound oracle reuse |
| **DoS against Trishula itself** | regex-catastrophic bodies, huge decodes, h2 rapid-reset, schema-bomb JSON depths | parser resource budgets per request (input/depth/decode caps), Vectorscan has no catastrophic backtracking, h2 settings caps, admission body-size ladder |
| **Debug-body samples as data leak** | `debugBodies: true` writes payloads to logs | redaction pipeline (header/token always; body only under CRD flag + purpose binding), per-tenant sample budget, retention config |
| **Fail-open regression** | misconfig silently flips a protected route to bypass | schema requires explicit `failureMode`; preflight admission denies `failClose` routes resolving to engines with no healthy replicas; drift alert when enforce-mode route lacks engine coverage |

### 18.3 Abuse of Trishula as vantage

- The engine is a trusted proxy: it sees tenant payloads. Network policy confines engine egress to pool CIDRs + the telemetry collector. No direct egress exists beyond the declared upstreams.
- OTel payloads (verdict metadata, ban evidence) are sensitive: redaction applies to telemetry exporters as to logs (§15.4).
- The ban ledger is an *attack record*: treat access like access to audit logs. The read paths are RBAC-scoped (`trishulactl ban list` requires cluster-reader-class RBAC).

### 18.4 What is explicitly trusted

The trusted set:
- the gateway's TLS termination and steering marks
- the kernel BPF verifier
- the node kernel
- OCI registry integrity
- CRD RBAC below the operator This trust is what keeps Trishula small. Residual risks are documented, not hidden.

<div class="pagebreak"></div>

## 19. Reference Implementation

**Repo footprint (D6 in §2.6):** GitHub org **`trishula-dev`** (github.com/trishula-dev). Repos: `trishula` (product, Apache-2.0; the tree below is its seed). `website` carries trishula.dev (the docs site). `rules` opens at Phase 1+ for curated community CEL + exclusion sets, once external contributions start. The bare handle `trishula` is a dormant user account; the product repo is `trishula-dev/trishula`.

The starting points are minimal but honest. The PoC proves the ladder end to end (build notes in §20). Repo layout:

```
trishula-dev/trishula/           # product repo (Apache-2.0) — §19/TR-01 seed
├── api/v1alpha1/                # CRD types (controller-gen from Go structs)
│   ├── wafpolicy_types.go
│   ├── apispec_types.go
│   ├── ruleset_types.go
│   └── banpolicy_types.go       # §13 constants + weights + mode
├── cmd/
│   ├── shield/                  # DaemonSet loader (cilium/ebpf)
│   ├── engine/                  # userspace WAF server (proxy + ext_proc transports)
│   ├── operator/                # CRD controller + compiler
│   └── trishulactl/             # ban list/release, capacity-plan, policy lint
├── bpf/                         # C sources, CO-RE (vmlinux.h, bpftool gen)
│   ├── shield_xdp.c             # XDP ACL/floods/ban-table/verdict-cache
│   ├── flow_tc.c                # TC classifier, ringbuf events
│   └── include/prd.h
├── internal/
│   ├── engine/ingest.go         # ringbuf drain → transaction assembly
│   ├── engine/ladder.go         # S0–S7 short-circuit evaluation
│   ├── engine/coraza/           # CRS evaluator adapter
│   ├── engine/cel/              # CEL rule compile+eval (cost-budgeted)
│   ├── engine/matcher/          # Vectorscan DB build/refresh
│   ├── engine/schema/           # OpenAPI positive security + discovery
│   ├── engine/bots/             # JA4/header/behavioral detectors
│   ├── engine/rateban/          # §13.2 algorithms + §13.3 ScoredWindowBan v1
│   ├── engine/ml/               # ONNX scorer + feature views
│   ├── engine/otel/             # traces/metrics + OTLP log export (§15)
│   └── proxy/                   # upstream forwarder (transparent, no endpoint logic)
├── manifests/                   # Helm/Kustomize; reference NGF Gateway + HTTPRoute bundles
├── docs/academy/                # §7 teach-the-web modules
├── lab/                         # kind + NGF scripted scenarios (the DX1 lab lives here)
├── rules/                       # CEL rules + CRS exclusion sets shipped by the project (D6: with the code)
│   ├── cel/                     # curated CEL rules, parity-tested, versioned with the engine
│   └── exclusions/              # CRS exclusion sets per integration profile (§16.5)
└── test/
    ├── crs-differential/        # CRS regression corpus runner (§11.8)
    ├── ban-conformance/         # §13.3 spec-reproduction conformance test
    └── bench/                   # wrk/vegeta/h2load scenarios (§17.2)
```

### 19.1 Stage sketches from the code (v0 PoC)

**Shield: TC ingress classifier with ring-buffer event (C, libbpf CO-RE):**

```c
// bpf/flow_tc.c — TC ingress classifier: eth0 and pod veths.
// Parses L3/L4 + fast-path HTTP metadata, emits event to ring buffer
// for the userspace engine. XDP (shield_xdp.c) handles drop-class verdicts
// (ACL, floods, ban_table hits) earlier in the path.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6

// Ban table: written by the engine (via the shield), enforced here at line rate.
// Keys are family-discriminated (dual-stack; a bare __u32 cannot hold an IPv6
// address and a /48 prefix would alias its contained hosts).
#define KEY_AF_INET  4
#define KEY_AF_INET6 6
struct ban_key     {
    union {
        __be32 v4;              // network byte order; upper 12 bytes zeroed
        struct in6_addr v6;
    } addr;
    __u8 family;                // AF_INET / AF_INET6 — explicit, not inferred
    __u8 key_class;             // ip | ja4_cluster | prefix
};
struct ban_val     { __u64 until_ts; __u8 tier; __u16 reason_code; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 20);
} ban_table SEC(".maps");

// Flow event streamed to userspace engine (ring buf, MPSC)
struct flow_event {
    __u64 ts_ns;
    __u32 saddr, daddr;
    __u16 sport, dport;
    __u8  tcp_flags;
    __u32 mark;             // gateway steering tag
    __u16 payload_len;
    __u8  http_seen;        // plaintext HTTP/1.x detected in first bytes
    __u8  h2_preface;       // HTTP/2 magic detected
    __u8  tls_seen;
    char  path_hint[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MiB per node
} events SEC(".maps");

struct verdict_key {
    union {
        __be32 v4;
        struct in6_addr v6;
    } addr;
    __u8 family;
    __u16 port_class;
};
struct verdict_val { __u8 action; __u64 until_ts; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 20);
} verdict_cache SEC(".maps");

struct flow_key  {
    union {
        __be32 v4;
        struct in6_addr v6;
    } addr;
    __u8 family;
    __u16 sport, dport;
};
struct flow_stat { __u64 syn_ts; __u32 req_bytes; __u16 seg_count; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 18);
} flow_stats SEC(".maps");

static __always_inline int classify_flow(struct __sk_buff *skb, void *data, void *data_end) {
    // bounded header walk (eth->ip->tcp), ban/verdict probes, rate counter update;
    // emits flow_event; on ban_table hit → TC_ACT_SHOT (enforcement, no userspace round-trip)
    return TC_ACT_OK;
}

SEC("tc")
int tc_ingress_waf(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u16 h_proto;
    if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), data + offsetof(struct ethhdr, h_proto)) < 0)
        return TC_ACT_OK;
    if (h_proto != bpf_htons(ETH_P_IP) && h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;
    return classify_flow(skb, data, data_end);
}

char LICENSE[] SEC("license") = "GPL";
```

Build: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`. Compile with clang `-O2 -g -D__TARGET_ARCH_arm64 -c`. Load with cilium/ebpf. Objects are generated via bpf2go in CI.[94][126]

**Engine: ring-buffer drain (Go, cilium/ebpf):**

```go
// internal/engine/ingest.go — consume shield events, assemble transactions.
package engine

import (
    "context"
    "encoding/binary"
    "bytes"
    "log/slog"

    "github.com/cilium/ebpf/ringbuf"
)

type FlowEvent struct { // mirrors bpf/flow_tc.c struct flow_event
    Timestamp    uint64
    SrcIP, DstIP uint32
    SrcPort, DstPort uint16
    TCPFlags     uint8
    Mark         uint32
    PayloadLen   uint16
    HTTPSeen     uint8
    H2Preface    uint8
    TLSSeen      uint8
    PathHint     [128]byte
}

func (e *Engine) DrainShield(ctx context.Context, rd *ringbuf.Reader) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case rec, ok := <-rd.Read():
            if !ok { return nil }
            var ev FlowEvent
            if err := binary.Read(bytes.NewReader(rec.Raw), nativeEndian, &ev); err != nil {
                slog.Warn("bad flow event", "err", err); continue
            }
            e.txMgr.NoteFlow(FlowToKey(ev)) // attach metadata to TX context
        }
    }
}
```

**Ladder short-circuit (Go) — seven families, first decisive verdict wins:**

```go
// internal/engine/ladder.go — S0–S7 evaluation with phase short-circuit.
type Verdict struct {
    Action    Action      // Allow | Log | Block | Challenge | Ban
    Rules     []RuleID
    Score     TxScore     // CRS-style anomaly accumulator + ban score inputs
    Phase     Phase       // RequestHeaders .. ResponseBody
    Features  FeatureView // for ML scorer (§14 FeatureView)
    CacheKey  CacheKey    // content+source-keyed; ban-worthy → kernel ban_table
    BanInput  BanEvent    // weight-contributing events for §13.3
    Telemetry []TelemetrySink
}

func (e *Engine) EvaluateTx(tx *TxContext) *Verdict {
    if v := e.kernelHits.Check(tx); v != nil { return v }        // S0: bans + cached verdicts
    if v, hit := e.matcherDB.QuickEval(tx.View()); hit {          // S1: Vectorscan fast path
        return e.resolve(v, tx)
    }
    v := e.crs.Evaluate(tx)             // S2: reference fidelity
    v.Merge(e.celRules.Evaluate(tx))    // S3: developer DSL
    if ap := e.schemas.Lookup(tx.Route); ap != nil {
        v.Merge(e.schemaValidator.Validate(tx, ap))              // S4: positive security
    }
    v.Merge(e.bots.Score(tx))           // S5: bot evidence (consensus policy)
    v.Merge(e.rateBan.Observe(tx))      // S6: rate windows → breach/ban events
    v.Merge(e.ml.LocalScore(tx))        // S7: ONNX, <1ms budget, async fallback
    return e.resolve(v, tx)
}
```

**`WAFPolicy` + `BanPolicy` CRD v0 sketches:**

```yaml
apiVersion: trishula.security/v1alpha1
kind: WAFPolicy
metadata:
  name: chat-completions
  namespace: ai-platform
spec:
  defaultAction: block        # fail-closed for this route class
  modes: { inline: true, shield: true, shadow: false }
  ruleSets:
    - name: owasp-crs
      source: { crsVersion: "4.x", profile: PL2 }
      exclusions: []
  customRules:
    - cel: |
        request.method == "POST" &&
        path.matches("/v1/chat/*") &&
        size(request.body.?json.messages) > 128
      action: block
      phase: request_body
      tags: [ai, rate-context]
  schema:
    apiSpecRef: ai-platform/chat-completions-v1
    mode: enforce             # learn | enforce | report
  botPolicy:
    knownGood: chat-healthcheckers
    consensus: 2of3
  ml:
    anomalyModelRef: ai-platform/trishula-anomaly-v1
    mode: shadow
    semanticJudge: { async: true, verdictTTL: 24h }
  failureMode: failClose      # explicit, never defaulted silently (§18.2)
  telemetry:
    otlp: { endpoint: otel-collector.observability:4317, logs: true, traces: true, metrics: true }
---
apiVersion: trishula.security/v1alpha1
kind: BanPolicy
metadata:
  name: chat-completions-bans
  namespace: ai-platform
spec:
  mode: shadow                # shadow-first, same ladder as rules (§13.3)
  constants: { findtime: 10m, threshold: 10, bantime: 10m, backoff: 2, maxBantime: 24h }
  weights:
    crsCritical: 5
    crsWarning: 2
    botConsensus: 4
    botSingle: 1
    rateBreach: 3
    schemaViolation: 2
    authFailure: 2
    kernelBurstFlag: 3
  decayHalfLifePct: 20        # % of findtime
  prefixEscalation: { enabled: false, minKeys: 8, window: 10m }
  rate:
    routes:
      - prefix: /v1/chat/
        algorithm: slidingWindow   # tokenBucket | slidingWindow | ewma
        keys: [ip]
        limits: { "1m": 30, "5m": 100 }
      - prefix: /v1/auth/login
        algorithm: slidingWindow
        keys: [ip, jwt.sub]
        limits: { "5m": 5 }
```

**Upstream forwarder note:** the engine's forward pass is minimal by design. It resolves the steered Service endpoints (endpoint slices; honoring gateway-set headers; EPP-selected pod metadata passes through untouched). It preserves hop-by-hop semantics and streams responses with bounded chunk buffering. No endpoint-picker logic lives in the WAF. Verification runs against §10's contract tests.

**ext_proc wire contract (the activation stage).** The transport is gRPC bidirectional streaming (`envoy.service.ext_proc.v3.ExternalProcessor`). Stages are honored per gateway `mode` (request headers, body BUFFERED/STREAMED, response headers/body). The `ProcessingResponse` immediate-response serves block/ban (local 403/429 + `Retry-After`). Gateway dynamic metadata is read only for policy lookup (never trusted as payload fact). The server writes verdicts, matched-rule IDs, anomaly and ban flags to its own metadata namespace. It never mutates EPP's `x-gateway-destination-endpoint` keys[43]. Per-gateway filter ordering (WAF↔EPP) is operator-emitted configuration. Failure semantics follow the gateway's ext_proc fail-open and fail-close config. The same `failureMode` CRD field carries the expression; operators keep one vocabulary.

<div class="pagebreak"></div>

## 20. Risks, Mitigations & Phasing

### 20.1 Risk register

| ID | Risk | L | I | Mitigation |
|----|------|---|---|------------|
| R1 | eBPF verifier rejects complex L7 parse | H | M | kernel parsing bounded + tail-call bounded; full parsing in userspace; verifier-friendliness is a CI check |
| R1b | Ringbuf overflow under attack burst | M | H | ring sizing + auto-scale trigger + kernel verdict/ban pre-seeding |
| R2 | CRS-in-Go parity gaps vs reference engines | M | H | differential suite in CI (§11.8); parity gate before engine GA |
| R2b | Vectorscan matcher DB memory (CRS-scale) | M | M | subset selection by frequency; block-mode compile; ~100s MB budget validated in CI |
| R3 | Gateway-API version friction across data planes | M | H | §10 contract tests in CI against NGF reference + one secondary (Envoy GW); pin supported versions; engine stays a plain Service backend |
| R4 | Engine-owned TLS (secondary mode) doubles cert management | L | M | optional, feature-gated; gateway-owned termination is the default |
| R5 | ML evasion (mimicry/probing) | M | M | perturbability-scored features; probe rate-limits; shadow-first; ensembles |
| R6 | ML verdict latency breaks inline budget | M | H | ONNX hard budget + async fallback; async judge never blocks |
| R7 | Fail-closed misconfigured → outage | L | H | shield fail-open default; inline per-policy explicit `failureMode`; preflight admission checks + guardrail docs |
| R7b | Streaming responses break response inspection | M | M | bounded reassembly windows; response inspection optional per route |
| R8 | Multi-tenancy rule bleed | L | M | CRD namespacing; per-tenant compiled bundles |
| R9 | Upstream OSS velocity (CRS 4→5, CRSLang) | M | L | track the spec, not releases; differential suite decouples |
| R10 | kTLS/uprobe workloads bypass L7 visibility | M | L | shield still owns L3/L4 + metadata; documented visibility contract per mode (§9.7) |
| R11 | Ban FPs lock out shared-egress users (CGNAT/office NAT) | — | M | §13.3 prefix-escalation off by default; per-identity keys; BanRelease CR; `BanRateAboveBudget` alert; ban evidence records make FPs diagnosable in minutes |
| R12 | NGF-specific assumptions leak into "portable" code | M | M | §10.5 honest-delta table reviewed per release; secondary-gateway CI lane (Envoy GW) keeps abstractions honest |

### 20.2 Phasing

**2026.01-rc1 (2026-10-10) — the PoC cut.** The shield DaemonSet carries XDP ACL + ban/verdict caches + TC flow events → ringbuf. The Go engine drains, parses HTTP/1.1 plaintext and logs verdicts. The engine sits behind NGF steering in kind. CRS runs at PL1 via the Coraza path. The CRD round-trip runs apply → compile → load. The differential suite ships the corpus gate. **Exit criteria:** < 10 ms inline (unoptimized); 100% verdict telemetry; a working CRD round-trip; proven NGF steer-to-engine (§10.3 lab green).

**2026.01-rc2 and rc3 (2026-10-23 and 2026-10-24) — the capability cuts.** Performance hardening reaches §17 targets. The Vectorscan matcher DB ships with its differential gate. The cuts shipped learn mode, API discovery and behavioural bot detection; the §13.2 rate algorithms; ScoredWindowBan shadow→enforce with `BanRelease`; the OTel pipeline (§15). **docs/academy Modules 1, 3, 4 + the DX1 lab ship.** NGF reference manifests + one secondary-gateway CI lane complete the phase.

**The GA track (the bare `2026.01` cut, then the calendar trains).** ML enforcement ships with a promotion workflow. The async semantic judge ships with a verdict cache. Behavioral DoS detectors cover slowloris and rapid-reset shapes. Prefix escalation goes GA (opt-in); the full `trishulactl` surface ships; academy Modules 2 & 5 land. The socket-plane L7 fast path gets its design note + `WAFPolicy`→eBPF template spike behind the §9.9 evaluation gate. The DPU (BlueField-class) shield port and the OpenShift/multi-arch builds enter evaluation and build lanes.

**The post-GA trains.** The lane carries ext_proc no-hop activation on Envoy-family estates. The re-encryption leg of the TLS-termination lane (TLS inspection on the egress side) is the named post-GA boundary of TR-203. The PQC signature migration (the CA/cert chain) follows the 2026.02/03 trains. The response-side schema/exfil guard and EPP-deep integrations follow where GIE composes further.

### 20.3 Open questions

1. **Coraza-embedded vs from-scratch evaluator** — the recommendation stands: embed Coraza as the reference evaluator (CRS fidelity + WASM extension). Build the compiled fast path + CEL natively. Composition, not fork.
2. **Vectorscan as the matcher** (Intel Hyperscan closed-source since 5.5[173][189]; Vectorscan OSS, Suricata-backed[172]) — the direction is confirmed. The rc1 cut validated the ARM64 + Go bindings.
3. **Kernel verdict/ban authority** — userspace decides; the kernel enforces. The recommendation keeps the kernel decision-free permanently. In-kernel rule evaluation fails the auditability test (§13.3) even where the verifier would permit it.
4. **Re-encryption toward pools** — the default keeps east-west plaintext in-cluster (mesh mTLS is a non-goal). The gateway handles the north edge. The secondary engine-TLS mode stays feature-gated for passthrough estates. The mode's inline HTTP/3 listener (TR-203 L3) runs under the same opt-in gate. It adds no upstream re-encryption.
5. **Tokenization boundaries** — Trishula sees post-tokenized payloads where an AI gateway sits in path; no token-vault responsibility. Where no AI gateway exists, Trishula's redaction pipeline (§15.4) is the payload-hygiene layer.
6. **Ban policy defaults per vertical** — the §13.3 constants are sane general defaults. Per-vertical presets (API-first SaaS vs auth-heavy B2C) ship as documented `BanPolicy` recipes in Phase 1+. The presets feed real tuning data back into the defaults.
7. **Composition re-evaluation (Appendix E watch-list):** the eBPF-native cousins (Synapse, Moat, MicroWAF — E.2) evolve quickly. When a cousin reaches that shape before the post-GA trains, re-run the borrow-vs-build analysis for that layer. No overlapping code ships meanwhile. The differential suite and the CRD compiler are the pieces worth keeping regardless.

<div class="pagebreak"></div>

## 21. Success Metrics & Adoption Gates

A developer-first spec measures **adoption**, not just detection:

| # | Metric | Gate |
|---|--------|------|
| M1 | CRS verdict parity on the differential suite | 100% applicable rules, CI-blocking |
| M2 | Inline p99 added latency (8KB, full CRS) | ≤ 1.5 ms, CI-blocking on benches |
| M3 | DX1 lab: clone → first enforced rule | ≤ 15 min, nightly-timed |
| M4 | Docs examples executed in CI | 100% |
| M5 | Academy modules shipped with runnable labs | 3 of 5 at Alpha, 5 at GA |
| M6 | Ban FP rate in shadow on reference corpus | ≤ budget set per route class; `BanRateAboveBudget` never fires in steady state |
| M7 | Uninstall kernel residue | zero objects, CI-asserted |
| M8 | NGF reference lab green (steer/readiness/429/h2c/shadow/uninstall) | CI-blocking per release |
| M9 | Time-to-enforce RuleSet apply | ≤ 5 s |
| M10 | OTel verdict records schema-valid | 100% (schema pinned `trishula.verdict.v1`) |

**Adoption is the real success metric** (§2.4): clusters where developers — not a security team — maintain most `RuleSet`/`BanPolicy` CRs. Contribution telemetry measures it; the project publishes quarterly (opt-in, aggregate).

<div class="pagebreak"></div>

## Appendix A: Roadmap Notes

- **HTTP/3:** the QUIC ingress posture is a tracked evaluation, not a runtime claim. QUIC's UDP transport moves the kernel-side story (XDP sees UDP floods the same way; QUIC packet framing needs userspace analysis). The academy module teaches the why before the product carries the claim. TR-203 L3 files the evaluation's first live leg at the engine (the dated entry below); this bullet's kernel-side posture stays.
- **TR-203 L3 — the engine inline H3 listener (opt-in):** the TR-34 TLS mode's responses advertise the h3 alternative and the mode answers h3 requests through its own ladder ([TR-203 #264](https://github.com/trishula-dev/trishula/issues/264), leaf 3). The `--h3-listen` flag opens the QUIC leg (`cmd/engine/h3.go`; [ADR-0006](adr/0006-inline-h3-listener.md)). The leg carries the same TLS cert pair. The QUIC handshake carries the unchanged L4 key-exchange profile. The h1/h2 responses carry the alt-svc advertisement. The flag off = no UDP surface; the default stays gateway-terminated. The 0-RTT posture reads reject: the transport accepts no early data. The listener pins no session-resumption material ([the posture record's dated read](design/h3-ingress-posture.md)).
- **Post-quantum:** termination at the gateway keeps Trishula cipher-agnostic. The PQ handshake (when negotiated) is the gateway's, on the client↔gateway leg; nothing in the shield or engine changes shape. The curriculum documents hybrid X25519+ML-KEM reality and its fingerprinting effects (client PQ preferences are themselves signal). The product carries no PQ data-plane claims.

  **Post-quantum readiness notes (TR-30).** PQ posture is a documentation concern with four concrete, product-side statements:

  1. **Hybrid PQ key exchange is arriving client-side, independently of Trishula.** X25519MLKEM768 is an IETF standard [324]: client share 1,216 bytes vs 32 for bare X25519. It is default-on in Chrome 124+ (ML-KEM variant since 131) [325]. The list continues: Firefox 132+, Go 1.24's `crypto/tls` [326], OpenSSL 3.5. Any TLS stack behind Trishula may already negotiate PQ key agreement. The motivation is harvest-now-decrypt-later: a recorded session stays secret only if its key exchange is PQ-secure. That calculus belongs to the gateway operator, not to the WAF — no product claim follows.
  2. **Termination altitude is the product decision, and PQ does not change it.** Gateway-owned termination (the default) keeps Trishula cipher-agnostic; the engine sees plaintext post-termination, exactly as with classical sessions. The engine-TLS secondary mode (§6.3, TR-34) inherits the same agnosticism. The ladder inspects what the TLS termination yields, whatever group negotiated at handshake time.
  3. **Signal effects are real and belong to the academy modules — not to product claims.** Hybrid key shares inflate the ClientHello (~1,200 bytes; multi-packet ClientHellos and middlebox compatibility effects are measured in the field [327]). Client PQ preference is JA3/JA4-visible signal [328], and a spoofable one [329] (see also [330]'s authentication-side asymmetry discussion). The curriculum teaches the delta as signal-with-caveats, never as an anti-spoofing control.
  4. **v1 carries no PQ data-plane claims** (§6.3 non-goal; the sibling discipline is the HTTP/3 entry above). PQ affects key agreement and signatures on hop 1 of the path — not the WAF's detection surface. PQ *authentication* (ML-DSA certificates [330]) is a separate, harder client+server migration, likewise out of scope for the product surfaces. The modules teach the 2026-timeframe asymmetry: PQ encryption is broadly deployed; PQ authentication is not.
- **Socket-plane L7 fast path:** a tracked design study (specification §9.9). The mechanism: kernel enforcement of header-class policies at the socket layer via `strparser`/kTLS, with synthesized per-policy programs. No body inspection and no HTTP/3. The kernel-module dependency and the verifier envelope are decided before any implementation claim.

- **TR-203 L5 — the JA4/PQC corpus and the QUIC Initial read:** the botdef's JA4 corpus gains the PQC vectors ([TR-203 #264](https://github.com/trishula-dev/trishula/issues/264), leaf L5). The corpus pins a captured Go offer twice: the X25519MLKEM768 default and the GODEBUG `tlsmlkem=0` baseline. The KEX offer uses extension data: the RFC 10024 group list 4588 (0x11EC), 4587 (0x11EB), 4589 (0x11ED); the client share carries 1,216 bytes against 32 for bare X25519. ja3's group list carries the shift. The JA4 token stays stable across the same stack's KEX flip. The token shifts only with a changed cipher, extension or signature set. The QUIC Initial-packet fingerprint read is the designed probe: [the design note](https://github.com/trishula-dev/trishula/blob/main/docs/design/quic-initial-fingerprint-read.md) files the RFC 9001 boundary. The header plane reads at eBPF. The ClientHello shadow decrypts in userspace. The kernel counts and drops ([§9.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory)). Probe P2b stays PENDING until a recorded run lands.

- **TR-203 L2 — the QUIC-ingress lab topology:** the kind/OrbStack lab carries the h3 listener leg ([TR-203 #264](https://github.com/trishula-dev/trishula/issues/264), leaf L2). The record: [the HTTP/3 ingress posture record](https://github.com/trishula-dev/trishula/blob/main/docs/design/h3-ingress-posture.md) files the plan. This leg = the plan's step 2. The lab terminator pod terminates the QUIC client leg (UDP :443) plus the TLS leg (TCP :443). It speaks h1 upstream to the engine Service (the record's F2 legs). The terminator image = the lab's NGF 2.7.2 dataplane build. Its nginx carries `--with-http_v3_module`. NGF itself carries no h3 listener row. The record's N8 holds: the operator owns the topology; the lab terminator answers for the h3 leg. Three probes file recorded runs; the receipts sit on [the leaf issue](https://github.com/trishula-dev/trishula/issues/264). Probe P4 = the advisory [h3spec](https://github.com/kazu-yamamoto/h3spec) pass against the listener. The tool output joins no verdict (the record's N5). [The verdict-integration section](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#122-verdict-integration) reads the UDP/QUIC ban path. Probe P7 = the ban identity on the L1 kernel leg. A live `ban_table` row SHOTs the keyed source's QUIC-class flow. The re-addressed stream passes while the row stays live. One source per key; no connection-id bind ([the ban algorithm](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified) keys the source). The h3 hop of P8 = one real HTTP/3 request runs the whole path: terminator → h1 upstream → engine → echo. The response reads the same view head with the engine's `X-Trishula-Hop` marker. The probes stay advisory lab material: [the topology gate](https://github.com/trishula-dev/trishula/blob/main/lab/dx1/h3-ingress-read.sh) carries the stage runners. No h3spec run enters CI.

- **Named-algorithm stability:** `ScoredWindowBan` is version-pinned by this document (v1). Any change ships as a new version + a conformance test — never a silent rewrite. CRS applies the same discipline to rule semantics.

<div class="pagebreak"></div>

## Appendix B: Glossary

| Term | Meaning |
|------|---------|
| **Positive security** | allowing only what a schema declares, rather than blocking what signatures match (§11.5) |
| **ScoredWindowBan** | §13.3's named, versioned temporary-ban algorithm — fail2ban-for-HTTP |
| **findtime / threshold / bantime** | fail2ban vocabulary, adopted for the ban constants |
| **The ladder** | the S0–S7 evaluation order over one compiled bundle (§2.3) |
| **Shield** | the per-node eBPF DaemonSet (XDP/TC hooks, kernel plane) |
| **Engine** | the userspace deep-inspection Deployment (the WAF proper) |
| **Ban table** | kernel map of active bans, enforced at XDP/TC without userspace |
| **Shadow mode** | evaluative-but-not-enforced; the promotion gate for every change |
| **NGF** | NGINX Gateway Fabric — the reference Gateway-API data plane |
| **JA4/JA4S** | TLS client/server fingerprints usable despite encryption |
| **FeatureView** | the versioned feature schema ML tiers consume (§14.2) |
| **Academy** | §7's teach-the-web curriculum (docs + labs) |
| **Socket-plane fast path** | the tracked §9.9 evaluation: header-class policy enforcement at the socket layer (strparser/kTLS), synthesized per policy |
| **Model A / Model B (TLS visibility)** | §9.7 posture: kernel plaintext via kTLS handoff (keys on-node) vs metadata-only signals (ClientHello/JA4/record framing) when keys are unavailable |

## Appendix C: Sources

Consolidated source list; inline numeric citations `[n]` resolve here. Carried from the research dossiers (Appendix D) with additions:

- **[39]** NGF + GIE inference extension how-to — <https://docs.nginx.com/nginx-gateway-fabric/how-to/gateway-api-inference-extension/>
- **[41]** GIE v1 API reference — <https://gateway-api-inference-extension.sigs.k8s.io/reference/spec/>
- **[43]** EPP protocol proposal 004 (v1.4.0 tag) — <https://github.com/kubernetes-sigs/gateway-api-inference-extension/blob/v1.4.0/docs/proposals/004-endpoint-picker-protocol/README.md>
- **[60]** <https://blog.cloudflare.com/how-to-drop-10-million-packets>
- **[61]** <https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations>
- **[66]** <https://blog.cloudflare.com/xdpcap>
- **[72]** <https://lwn.net/Articles/754659>
- **[75]** <https://dl.acm.org/doi/10.1145/3281411.3281443>
- **[76]** <https://github.com/facebookincubator/katran>
- **[79]** <https://blog.px.dev/ebpf-openssl-tracing>
- **[85]** <https://docs.cilium.io/en/latest/security/network/proxy/envoy>
- **[87]** <https://docs.cilium.io/en/stable/reference-guides/bpf/architecture>
- **[94]** <https://github.com/cilium/ebpf>
- **[95]** <https://nakryiko.com/posts/bpf-portability-and-co-re>
- **[96]** <https://docs.ebpf.io/linux/concepts/verifier>
- **[105]** <https://bpfconf.ebpf.io/bpfconf2025/bpfconf2025_material/Beyond%201M%20instructions.pdf>
- **[106]** <https://docs.ebpf.io/linux/concepts/tail-calls>
- **[126]** <https://ebpf-go.dev/guides/getting-started>
- **[128]** Vectorscan releases — <https://github.com/VectorCamp/vectorscan/releases>
- **[129]** Suricata Hyperscan docs — <https://github.com/OISF/suricata/blob/master/doc/userguide/performance/hyperscan.rst>
- **[132]** CRS migration pt6 FP tuning — <https://coreruleset.org/20260504/migrating-crs-3-to-4-part-6-tuning>
- **[133]** Coraza site — <https://coraza.io>
- **[134]** Coraza GitHub — <https://github.com/corazawaf/coraza>
- **[136]** Intel Hyperscan GitHub — <https://github.com/intel/hyperscan>
- **[137]** CEL spec GitHub — <https://github.com/google/cel-spec>
- **[139]** CRS v4.25.0 LTS announcement — <https://coreruleset.org/20260321/announcing-crs-v4-25-lts>
- **[141]** CRS README (license) — <https://raw.githubusercontent.com/coreruleset/coreruleset/main/README.md>
- **[142]** CRS migration pt1 overview — <https://coreruleset.org/20260330/migrating-crs-3-to-4-part-1-overview>
- **[145]** CrowdSec AppSec intro — <https://docs.crowdsec.net/docs/next/appsec/intro>
- **[146]** K8s CEL docs — <https://kubernetes.io/docs/reference/using-api/cel>
- **[147]** Vectorscan CHANGELOG raw — <https://raw.githubusercontent.com/vectorcamp/vectorscan/develop/CHANGELOG.md>
- **[149]** Envoy local rate limit proto — <https://raw.githubusercontent.com/envoyproxy/envoy/main/api/envoy/extensions/filters/http/local_ratelimit/v3/local_rate_limit.proto>
- **[154]** Coraza CHANGELOG (WASM/TinyGo, CRS4) — <https://github.com/corazawaf/coraza/blob/main/CHANGELOG.md>
- **[157]** Envoy Matching API (CEL matcher) — <https://envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/matching/matching_api>
- **[159]** Coraza 100x perf article — <https://medium.com/@jptosso/how-owasp-coraza-improved-performance-by-100x-38d982371ea9>
- **[161]** CRS regexp-assemble blog — <https://coreruleset.org/20190826/optimizing-regular-expressions>
- **[162]** CRS ReDoS blog — <https://coreruleset.org/20190425/regular-expression-dos-weaknesses-in-crs>
- **[165]** CRS crs-toolchain docs — <https://coreruleset.org/docs/6-development/6-2-crs-toolchain>
- **[167]** Trustwave transfers ModSecurity to OWASP — <https://owasp.org/blog/2024/01/09/ModSecurity.html>
- **[170]** CrowdSec bot detection docs — <https://docs.crowdsec.net/docs/next/appsec/bot_detection/intro>
- **[171]** CRS plugin registry — <https://github.com/coreruleset/plugin-registry>
- **[172]** Suricata/OISF Vectorscan support blog — <https://suricata.io/2026/09/29/why-vectorscan-matters-to-suricata-and-why-were-supporting-it>
- **[173]** Vectorscan README (license change, portability) — <https://raw.githubusercontent.com/VectorCamp/vectorscan/develop/README.md>
- **[177]** go-ftw CRS regression testing — <https://github.com/coreruleset/go-ftw>
- **[178]** OWASP CRS GitHub repo — <https://github.com/coreruleset/coreruleset>
- **[189]** Intel Hyperscan releases (v5.4.2 last OSS) — <https://github.com/intel/hyperscan/releases>
- **[192]** <https://github.com/openappsec/openappsec>
- **[196]** <https://github.com/chaitin/SafeLine>
- **[197]** <https://docs.wallarm.com/api-abuse-prevention/overview>
- **[201]** <https://openappsec.io/post/open-appsec-waf-docker-compose-deployment-new-capabilities>
- **[202]** <https://github.com/chaitin/SafeLine/releases>
- **[205]** <https://www.secrss.com/articles/74483>
- **[206]** <https://bbs.chaitin.cn/topic/9412>
- **[209]** <https://help.waf-ce.chaitin.cn>
- **[211]** <https://arxiv.org/html/2306.05494v5>
- **[215]** <https://arxiv.org/html/2512.23610v2>
- **[216]** <https://ar5iv.labs.arxiv.org/html/2312.13041>
- **[217]** <https://arxiv.org/abs/2603.25176>
- **[218]** <https://arxiv.org/html/2603.29403v2>
- **[219]** <https://arxiv.org/abs/2503.00596>
- **[222]** <https://link.springer.com/article/10.1007/s44443-026-01098-3>
- **[224]** <https://stribog.com/blog/nvidia-gpu-operator-mig-time-slicing-kubernetes-sharing>
- **[225]** <https://nops.io/blog/gpu-sharing-in-kubernetes>
- **[228]** <https://tildalice.io/gpu-vs-cpu-inference-cost-latency-benchmark>
- **[230]** <https://openreview.net/pdf?id=m5AntlhJ7Z5>
- **[234]** <https://arxiv.org/html/2506.09443v2>
- **[237]** <https://docs.openappsec.io/llms-full.txt>
- **[239]** <https://docs.openappsec.io/how-to/configuration-and-learning/track-learning-and-move-from-learn-detect-to-prevent>
- **[241]** <https://docs.openappsec.io/additional-security-engines/api-schema-enforcement>
- **[242]** <https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/user_guide/model_repository.html>
- **[243]** <https://youngju.dev/blog/ai-platform/2026-03-06-ai-platform-ml-model-monitoring-drift-detection-evidently-mlflow.en>
- **[244]** <https://github.com/triton-inference-server/server/blob/main/docs/user_guide/model_management.md>
- **[249]** F5 WAF for NGINX overview (headline features, deployment options, NGINX One packaging) — <https://docs.nginx.com/waf/fundamentals/overview/>
- **[254]** NGF WAFPolicy + compiled bundles — <https://docs.nginx.com/nginx-gateway-fabric/waf-integration/overview>
- **[301]** NGF securityLogs destinations, logSource options, polling, fail-open — <https://docs.nginx.com/nginx-gateway-fabric/waf-integration/configuration>
- **[310]** CRS docs: engines (Coraza 100% CRS v4), anomaly scoring, PLs, staging via PL, commercial-integration caveats — <https://coreruleset.org/docs/index.print>
- **[312]** "fully compatible with OWASP CRS, except by DDOS and anti-bot protection"; roadmap (WASM, integrated DoS/bot) — <https://github.com/corazawaf/coraza/blob/master/README.md>
- **[316]** (canon: https://www.f5.com/company/blog/nginx/f5-nginx-modsecurity-waf-transitioning-to-eol/) — NGINX ModSecurity WAF EoL Mar 31 2024; CRS pivoting to Coraza — <https://www.nginx.com/blog/f5-nginx-modsecurity-waf-transitioning-to-eol/>
- **[318]** Trustwave EOS Aug 2021 / EOL Jul 1 2024 stewardship transfer; release timeline — <https://en.wikipedia.org/wiki/ModSecurity>
- **[322]** CRS tuning burden (4–8h, per-endpoint exclusions) — <https://www.systemshardening.com/articles/network/waf-rule-tuning/>
- **[324]** RFC 10024 — PQ/T hybrid key agreement for TLS 1.3: X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024, group registry (0x11EC), client share 1,216 B vs 32 B for X25519; pre-standard Kyber768 entries obsoleted — <https://www.rfc-editor.org/rfc/rfc10024>
- **[325]** Chromium — hybrid PQ key exchange default in Chrome 124; X25519MLKEM768 (FIPS 203) from Chrome 131 — <https://blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html> · <https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html>
- **[326]** Go 1.24 release notes — `crypto/tls` enables X25519MLKEM768 by default (`tlsmlkem` GODEBUG revert) — <https://go.dev/doc/go1.24>
- **[327]** Cloudflare — PQ keyshares to origins: ClientHello size effects, middlebox failures (~0.34% of scanned origins), HelloRetryRequest flow — <https://blog.cloudflare.com/post-quantum-to-origins/>
- **[328]** Cloudflare Radar — post-quantum TLS adoption telemetry — <https://radar.cloudflare.com/post-quantum>
- **[329]** JA4+ TLS client fingerprinting specification — <https://github.com/FoxIO-LLC/ja4>
- **[330]** Cloudflare — post-quantum authentication to origins: ML-DSA certificates, the encryption-vs-authentication deployment asymmetry — <https://blog.cloudflare.com/post-quantum-authentication-to-origins/>
- **[F-apisix]** Apache APISIX: open-source API/AI gateway — <https://apisix.apache.org/>
- **[F-bunkerweb]** BunkerWeb: open-source WAF / reverse proxy (AGPLv3) — <https://github.com/bunkerity/bunkerweb>
- **[F-higress]** Higress: AI-native API gateway (Envoy/Istio, Wasm plugins, GIE-conformant) — <https://github.com/higress-group/higress>
- **[F-ja4]** JA4/JA4S TLS fingerprint specification (FoxIO) — <https://github.com/FoxIO-LLC/ja4>
- **[F-janusec]** Janusec Application Gateway — <https://janusec.github.io/>
- **[F-microwaf]** MicroWAF: host-side WAF with XDP drop rates and CEL rules engine — <https://github.com/dcc-bigfred/microwaf>
- **[F-moat]** Moat (sitedata): eBPF-powered TCP/HTTP proxy agent with JA4+ and XDP filtering — <https://github.com/sitedata/moat>
- **[F-naxsi]** NAXSI (maintained fork) — <https://github.com/wargio/naxsi>
- **[F-ngf27]** NGINX Gateway Fabric 2.7 release announcement (Gateway API 1.6 conformance, external auth, TLS Terminate) — <https://blog.nginx.org/blog/nginx-gateway-fabric-2-7-gateway-api-1-6-conformance-external-authentication-and-fewer-snippets>
- **[F-ngxrl]** NGINX ngx_http_limit_req_module (rate limiting semantics) — <https://nginx.org/en/docs/http/ngx_http_limit_req_module.html>
- **[F-rfc9110]** RFC 9110: HTTP Semantics (429 + Retry-After) — <https://www.rfc-editor.org/rfc/rfc9110>
- **[F-spliff]** Spliff: correlating XDP and TLS via eBPF (L7 sniffer / EDR foundation) — <https://news.ycombinator.com/item?id=46663319>
- **[F-synapse]** Synapse (gen0sec/FoxIO): active NDR with eBPF/XDP enforcement, JA4+ blocking, proxy mode — <https://github.com/FoxIO-LLC/synapse>
- **[F-tempest]** TEMPEST-BREAKER: zero-allocation eBPF/XDP tarpit in Rust (AF_XDP, Count-Min sketch bans) — <https://medium.com/@okywoww/defeating-volumetric-ddos-at-the-network-edge-building-a-zero-allocation-ebpf-xdp-tarpit-in-rust-e44ed3d089a0>

<div class="pagebreak"></div>

## Appendix D: Research Dossiers

The design synthesizes five research dossiers (per-claim citations resolved in Appendix C):

- **R1 — Gateway-API steering, Inference Extension (EPP):** GIE/EPP ext_proc protocol and failure modes, NGF inference-extension integration, security-stage attachment patterns on Gateway-API data planes, the insertion variants (§10).
- **R2 — eBPF packet processing and L7 visibility:** XDP/AF_XDP/TC performance envelopes, verifier limits, CO-RE/BTF/bpf2go portability, TLS ciphertext visibility limits, prior-art eBPF WAF/IDS, ringbuf userspace-engine architecture (§8–9).
- **R3 — Rule engines and detection tech:** CRS 4.x coverage/FP/ReDoS history, Coraza performance and WASM status, Vectorscan vs Hyperscan closure, CEL/OPA DSL trade-offs, the OSS positive-security/bot/rate gap catalog (§11).
- **R4 — ML-powered WAF scenarios:** open-appsec/SafeLine/Wallarm patterns, detection literature (cascades, LLM-as-judge, evasion research), ONNX/Triton latency envelopes, drift tooling (§14).
- **R5 — Commercial WAF capability catalog:** F5 WAF for NGINX / AWAF / XC WAAP feature-by-feature (signatures + cadence, positive security, API discovery, bot defense, behavioral DoS, credential stuffing, telemetry) with the OSS gap analysis per capability — the "what good looks like" reference list (§3.2 P5, §4.3). *(Historical-research citations only — no F5 product dependency exists in the design.)*

<div class="pagebreak"></div>

## Appendix E: Similar Projects — and Why We Did Not Build On Them

An honest field survey. The rule applied to every project below: **composition over forking, borrowing over rebuilding, and a stated reason when neither is possible.** §4.1 covers the WAF-shaped core. This appendix covers everything adjacent: eBPF security tools, runtime-enforcement platforms, gateway/plugin stacks and the temporal-ban lineage. The "why not build on X" question reaches beyond projects that call themselves WAFs.

### E.1 The full catalog

```mermaid
flowchart TB
    subgraph EBPFW["eBPF-native network security"]
        SYN["Synapse<br/>(XDP NDR + proxy)"]
        MOAT["Moat<br/>(XDP edge proxy)"]
        MW["MicroWAF<br/>(host WAF, CEL)"]
        SPLIFF["Spliff<br/>(L7 EDR sniffer)"]
        TB["TEMPEST-BREAKER<br/>(XDP tarpit experiment)"]
        LD["L4Drop / Katran lineage<br/>(Cloudflare XDP)"]
    end
    subgraph RUNTIME["K8s runtime / network enforcement"]
        CIL["Cilium + Hubble"]
        TET["Tetragon<br/>(in-kernel policy)"]
        TRA["Tracee"]
        KA["KubeArmor"]
        FAL["Falco"]
        OBI["Beyla / OBI"]
    end
    subgraph WAFS["OSS WAF engines / stacks"]
        COR["Coraza"]
        MOD["ModSecurity (libMOSC)"]
        NAX["NAXSI"]
        BW["BunkerWeb"]
        SL["SafeLine"]
        OA["open-appsec"]
        CS["CrowdSec"]
    end
    subgraph GW["Gateways with security plugins"]
        APX["APISIX"]
        HG["Higress"]
        JNS["Janusec"]
    end
    subgraph BAN["Temporal-ban lineage"]
        F2B["fail2ban"]
        CROWD["CrowdSec remediation"]
    end
    COR -->|"reference evaluator"| T["Trishula<br/>(composition)"]
    CIL -->|"two-plane pattern"| T
    SYN -->|"JA4+ altitude proof"| T
    F2B -->|"ban UX"| T
    style T fill:#e0f2fe
```

*Figure 15. What Trishula composes from where — and the categories it deliberately does not join.*

### E.2 eBPF-native network security (closest cousins)

| Project | What it genuinely is | What it does well | Why Trishula did not build on it (the irreducible gap) |
|---------|---------------------|-------------------|--------------------------------------------------------|
| **Synapse** (FoxIO/gen0sec)[F-synapse] | Active NDR: XDP kernel enforcement + optional inline proxy, JA4+ fingerprint suites, Wirefilter WAF, rate limiting, CAPTCHA, multi-backend firewall (XDP→nftables→iptables) | The closest eBPF cousin to Trishula's shield+proxy split; JA4+ as first-class blocking identity; kernel-speed enforcement with userspace fallback; Windows support | Host/edge-appliance-shaped (single binary, config files, SIEM event stream) — not a Kubernetes policy system: no CRDs, no GitOps rule lifecycle, no Gateway-API steering citizenship, no shadow-first promotion, no CRS corpus, no positive security, no per-tenant isolation. Trishula borrows its *altitudes* (kernel enforcement + inline deep inspection) and its JA4+ posture, and builds the missing CRD/gateway/parity machinery on top. A composition would still mean writing everything this spec specifies — with a config-file core to unwind. The `FoxIO-LLC/synapse` record is a fork of [`sitedata/moat`](https://github.com/sitedata/moat). The GitHub license endpoints read `NOASSERTION` (ELv2 badges on both records). `NOASSERTION` carries license risk for any future adoption |
| **Moat** (sitedata)[F-moat] | Rust XDP reverse proxy + full JA4+ suite + threat-intel API + CAPTCHA + ClamAV content scan | Clean XDP packet filtering; complete JA4+ capture; ACME automation | Edge proxy appliance coupled to a commercial intel API (Arxignis) for rules and bot scoring — data-plane decisions keyed to a third-party service contradict the OSS/clean-egress design rule (§18.3); same non-K8s gaps as Synapse. Borrowed idea: fingerprint-identity blocking at kernel speed |
| **MicroWAF** (dcc-bigfred)[F-microwaf] | Host-side WAF for Linux/RPi: XDP drop rates, CEL-based rules engine, Redis-backed windows, per-MAC/IP L7 counting | Independently validated the CEL-for-WAF choice; honest small-host scope; embeds eBPF objects in the binary | Per-host, per-MAC/IP state model — no cluster policy, no multi-tenant route classes, no gateway integration, Redis as ban state (network dependency in the enforcement path, which §13.3's kernel-table design deliberately avoids). Borrowed idea: CEL as the authoring surface |
| **Spliff** (L7 EDR sniffer)[F-spliff] | XDP + sock_ops + uprobes correlating decrypted TLS buffers to TCP flows/PIDs; full HPACK HTTP/2 parsing; no-MITM visibility | The "golden thread" correlation pattern (packets ↔ decrypted bytes ↔ process) is the best-in-class answer to §9.7's kTLS visibility gap | A visibility engine, not enforcement: no rule lifecycle, no verdicts, no policy surface. Trishula's uprobes contract (§9.2) is where this pattern plugs in *if* app-internal-TLS visibility ships — as an integration, not a base |
| **TEMPEST-BREAKER** (experiment)[F-tempest] | Rust AF_XDP zero-alloc tarpit: Count-Min sketches per /24, token buckets, asymmetric L7 penalties | Memory-O(1) ban state under 100M-IP floods — the exact OOM-immunity argument §9.3's LRU sizing must handle | Blog-scale experiment (single-host, no policy surface); its sketches/token-buckets are textbook mechanics Trishula gets via standard maps + §13.2. Borrowed idea: fixed-memory adversarial accounting |
| **L4Drop / Katran** (Cloudflare/Meta lineage)[61][76] | Production XDP L3/L4 DDoS mitigations and XDP load balancing at hyperscale | Proof at 10+ Mpps/core that §9's budgets are real, not aspiration | Purpose-built L4 shapers — no HTTP semantics, no rules, no lifecycle. They validate §9 rather than compete with it |

**The common gap, stated once:** every eBPF-native project above stops at *network-shaped* policy (IPs, fingerprints, rates, drops). None compiles CRD policy into kernel maps + userspace evaluator chains as one artifact. None speaks Gateway API. None carries a signature corpus (CRS) or a positive-security model. None treats shadow-first correctness as a mechanism. The gap is exactly Trishula's §2 design decisions D1–D5.

### E.3 Kubernetes runtime/network enforcement (adjacent altitude, different job)

| Project | What it does | Why not the base |
|---------|-------------|------------------|
| **Cilium + Envoy** | eBPF CNI; L3/L4 policy in kernel, L7 via an Envoy hop | The validated two-plane pattern Trishula borrows deliberately (§3.3); but Envoy-as-L7 is a proxy with filters, not a WAF: no CRS corpus, no positive security, no ban lifecycle, no developer-facing rule language. Extending Cilium's Envoy layer would couple Trishula to Cilium's release/upgrade train — the WAF becomes part of the CNI, which every operator separately upgrades (§3.3) |
| **Tetragon** | In-kernel syscall/LSM policy (TracingPolicy CRDs → eBPF with Sigkill/override), now with in-BPF CEL | Runtime/process enforcement — syscalls, not HTTP sessions. No HTTP parser, no TLS, no request semantics. Its CRD→eBPF compile pattern is the confirmation of Trishula's operator-compiles-kernel-values design (§8.1.2); its in-BPF CEL validates CEL as the K8s-native expression language[147] |
| **Tracee** | eBPF runtime event engine, ATT&CK-mapped signatures | Process/forensics altitude, not HTTP; detection-only |
| **KubeArmor** | LSM/BPF-LSM per-pod policy enforcement | File/process/network-bind policy per pod; no HTTP request semantics, no ingress contract |
| **Falco** | Syscall event rules engine (CNCF graduated) | Log/event-shaped detection; no enforcement, no HTTP |
| **Beyla / OBI** | Zero-instrumentation OTel traces/metrics via eBPF | Proof that eBPF→OTLP pipelines work at scale (§15's posture); not a security control |

These tools are *complementary deployments*, not competitors. A Trishula cluster commonly runs Cilium/Tetragon for east-west + runtime (Trishula is explicitly not a mesh — §6.3). The distinction that matters: **none of them parses HTTP sessions as its enforcement object**. North-south HTTP protection stays unowned in that stack.

### E.4 OSS WAF engines and stacks (the direct family)

| Project | What it is | What we borrow | Why not build on it |
|---------|-----------|----------------|---------------------|
| **Coraza**[133][134] | Go WAF library, CRS-compatible, WASM plugins | **The reference evaluator — embedded, not forked** (§11.2): CRS fidelity, WASM extension | A library, not a product: no data plane of its own, no kernel altitude, no CRDs, no bot/rate/ban machinery, no steering contract. Building Trishula *on* Coraza means building all of that anyway — at which point Coraza-as-evaluator inside Trishula's operator/engine is the composition that preserves upstream CRS work |
| **ModSecurity / libMOSC**[167][318] | The historical engine; maintenance-mode after the nginx EOL[316] | Nothing mechanical — the cautionary tale: engine stagnation kills rule ecosystems | Deprecated trajectory; C-embedding would couple Trishula's engine to a stewardless codebase |
| **NAXSI** (wargio fork)[F-naxsi] | nginx module; drop-by-default + learned whitelists | The whitelist-learning philosophy (pre-echo of positive security) | nginx-module-coupled (the exact §3.2 P1/P2 shape), PCRE-bound, no kernel altitude, dormant upstream |
| **BunkerWeb**[F-bunkerweb] | nginx-based container WAF stack, ModSecurity+CRS core, Coraza plugin, ban-on-status, secure-by-default defaults | The "secure by default" DX stance; status-based auto-ban UX | nginx-container stack with a web UI — the appliance shape (P1/P2/P7) with AGPL constraints; no eBPF, no Gateway-API citizenship, ban logic is status-code heuristics not a specified algorithm (§13.3) |
| **SafeLine**[196][205] | Container WAF, nginx core, staged semantic/LLM pipeline | Staged cheap→heavy detection (§14's cascade shape) | docker-compose-first shape, nginx-coupled pipeline, central panel; no kernel altitude, no CRD lifecycle, no gateway contract |
| **open-appsec**[192][239][241] | ML WAF (2 models + context), positive security, CRDs on K8s | Learning→enforcement lifecycle with objective promotion gates (§14.2.6) | Enforcement depends on a central management plane; attachment model is sidecar/central, not Gateway-API steering; no eBPF altitude; ML model plane is not self-hostable-clean. The lifecycle idea survives the split from its architecture |
| **CrowdSec**[145][170] | Log/agent security engine + community blocklists + remediation components | Community intel as one ban input; the bouncer pattern | Log-tap altitude for HTTP (the fail2ban critique, §3.3); detection lives outside the wire; no HTTP session parser, no TLS fingerprinting at termination, no inline verdict path. As *feeder* or *bouncer* integration: fits. As base: wrong altitude |

### E.5 Gateways with security plugins (adjacent category)

| Project | What it is | Why not the base |
|---------|-----------|------------------|
| **APISIX**[F-apisix] | Open-source API/AI gateway (Apache/CNCF), 100+ plugins, rate limiting, OIDC, AI routing | A gateway, not a WAF: its security plugins are per-plugin breadth without a compiled policy artifact, kernel altitude, or CRS/positive-security depth; embedding WAF logic as gateway plugins re-couples protection to the gateway's release train — the opposite of Trishula's gateway-agnostic posture (§2.2) |
| **Higress**[F-higress] | Envoy/Istio-based AI-native gateway with Wasm plugin hub, GIE-conformant | Same category argument; its Wasm plugin surface is a documented extension point Trishula could target *for its estates* (as a processor/plugin), not the foundation of an eBPF product |
| **Janusec**[F-janusec] | Go application gateway with WAF/CC defense/OAuth2/ingress | Web-console-managed single-plane appliance; small community; no kernel altitude; a reminder that "gateway with WAF bolted on" is a well-trodden shape — Trishula's thesis is the opposite decomposition |

### E.6 The temporal-ban lineage (§13's ancestry)

- **fail2ban**[147]: the UX archetype — findtime/maxretry/bantime vocabulary, expiry, recidive jails — adopted wholesale in §13.3's constants, moved from log-tap to wire, from filesystem state to kernel map + ledger, from grep patterns to weighted scores with OTel evidence. Not extensible to HTTP sessions; not distributed; not observable beyond file logs.
- **CrowdSec remediation components** (crowdsec-blocklists, bouncers): the distributed/community evolution of the same idea — borrowed as an optional intel input (§4.2), not as the enforcement path.
- **sshguard / ssh-blame-class tools**: single-protocol ancestors; nothing past vocabulary to borrow.

### E.7 The synthesis rule

Every project above is good at its altitude. Trishula's reason to exist: **no project spans the altitudes this problem needs**. The altitudes:
kernel-speed enforcement; full-HTTP deep inspection; a signature corpus with parity discipline;
positive security; bot/behavior detection; a specified temporal-ban algorithm — all compiled from one
CRD surface a developer can read. The project also commits to teaching the wire (§7). Some projects own an altitude better: Coraza's CRS fidelity, Tetragon's in-kernel enforcement, Cilium's east-west. The design composes with them or defers to them explicitly. The honest boundary: Trishula is not a replacement for the stack below it. It is the missing north-south layer that makes the stack comprehensible to developers.
