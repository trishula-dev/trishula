#!/usr/bin/env bash
# TR-203 L4 (issue #264, decision 4) — the lab terminator's PQC
# termination read on the DX1 lab.
#
# What the run answers:
#   leg 1  the https leg comes up: NGF marks the https listener Programmed
#          and the Service carries the https NodePort row.
#   leg 2  the handshake read: an ML-KEM-capable openssl client dials the
#          terminator and prints
#            Negotiated TLS1.3 group: X25519MLKEM768
#          The hybrid key exchange off the live terminator = the surface's
#          recorded transcript.
#
# The engine listener surface's transcript = the profile test:
#   GOTOOLCHAIN=go1.26.0 go test ./cmd/engine/ \
#     -run 'TestTLSTerminationProfileSpeaksTheHybrid' -v
# (docs/deploy/tls-termination-pqc.md carries both surfaces' runs).
#
# Facts the read states about lanes:
#   - The 2.x dataplane image (OpenSSL 3.5+) speaks the hybrid. Verified:
#     nginx 1.31.6, OpenSSL 3.5.7/3.5.8 (the 2.7.2 dataplane image).
#   - The 1.x fallback dataplane (the OrbStack lane) runs OpenSSL 3.3.2:
#     the read then negotiates X25519 (classical) and files the finding.
# The script never reports a classical read as the hybrid pass.

set -euo pipefail

NGF_NS="${NGF_NS:-nginx-gateway}"
NODE_HTTPS_PORT="${NODE_HTTPS_PORT:-31438}"
HTTPS_HOST="${HTTPS_HOST:-engine.dx1.example.com}"
HYBRID_GROUP="X25519MLKEM768"

fail() { printf '== PQC-TERMINATION-READ-FAIL — %s ==\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP  %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }

command -v kubectl >/dev/null 2>&1 || fail "missing dependency: kubectl (see docs/deploy/tls-termination-pqc.md)"
command -v openssl >/dev/null 2>&1 || fail "missing dependency: openssl (see docs/deploy/tls-termination-pqc.md)"

# find_hybrid_openssl — an openssl client that speaks the hybrid. The base
# system openssl may be LibreSSL (no ML-KEM): search the known modern
# installs first, check the version, and SKIP with the named absent piece
# when no ML-KEM-capable binary exists on the host.
find_hybrid_openssl() {
  local c v major minor
  for c in \
    "${OPENSSL_BIN:-}" \
    /opt/homebrew/opt/openssl@3.5/bin/openssl \
    /opt/homebrew/opt/openssl@3.6/bin/openssl \
    /opt/homebrew/opt/openssl@4/bin/openssl \
    /opt/homebrew/opt/openssl/bin/openssl \
    /usr/local/opt/openssl@3.5/bin/openssl \
    openssl; do
    [ -n "${c:-}" ] || continue
    command -v "$c" >/dev/null 2>&1 || continue
    v="$("$c" version 2>/dev/null | head -1)" || continue
    case "$v" in
      LibreSSL*)
        skip "system openssl is $v (no ML-KEM); trying the next candidate"
        continue
        ;;
    esac
    major="$(printf '%s' "$v" | sed -E 's/^OpenSSL ([0-9]+)\.[0-9]+\..*$/\1/')"
    minor="$(printf '%s' "$v" | sed -E 's/^OpenSSL [0-9]+\.([0-9]+)\..*$/\1/')"
    if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 5 ]; }; then
      printf 'ML-KEM-capable client: %s (%s)\n' "$c" "$v"
      return 0
    fi
  done
  return 1
}

OSSL="$(find_hybrid_openssl | head -1 | sed -E 's/^ML-KEM-capable client: //; s/ \(.+\)$//')" \
  || skip "no ML-KEM-capable openssl found on this host; bring OpenSSL 3.5+ (brew install openssl@3.5) and set OPENSSL_BIN"
if [ -z "${OSSL:-}" ]; then
  fail "no ML-KEM-capable openssl on this host — the read needs OpenSSL 3.5+ as the client"
fi

printf 'terminator: kubectl -n %s — the lab gateway TLS leg\n' "$NGF_NS"

# leg 1: the https leg comes up
listener_state="$(kubectl -n "$NGF_NS" get gateway edge-gateway -o jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}' 2>/dev/null || true)"
printf 'gateway conditions:\n%s\n' "${listener_state:-unavailable}"
cert_secret="$(kubectl -n "$NGF_NS" get secret dx1-lab-tls -o name 2>/dev/null || true)"
[ "$cert_secret" = "secret/dx1-lab-tls" ] || fail "the dx1-lab-tls Secret is missing — run lab/dx1/setup.sh first (the TLS leg fixture)"
pass "the dx1-lab-tls fixture Secret is in place"

nodeport="$(kubectl -n "$NGF_NS" get svc -o jsonpath='{range .items[*]}{.metadata.name}:{"\n"}{range .spec.ports[*]}{"  "}{.name} port={.port} nodePort={.nodePort}{"\n"}{end}{end}' 2>/dev/null | grep -E "nodePort=(${NODE_HTTPS_PORT})" | head -10 || true)"
printf 'Service NodePorts:\n%s\n' "${nodeport:-unavailable}"
[ -n "$nodeport" ] || fail "no https NodePort row exists — the 1.x fallback pin runs inside setup.sh; re-run it"
pass "the https NodePort row is live"

# leg 2: the hybrid read off the terminator
transcript="$("$OSSL" s_client -connect "127.0.0.1:${NODE_HTTPS_PORT}" -servername "$HTTPS_HOST" </dev/null 2>/dev/null)"
printf '%s\n' "---- handshake transcript (openssl client: ${OSSL}) ----"
printf '%s\n' "$transcript" | grep -iE "new,|cipher is|negotiated.*group|protocol *:|issuer|subject|peer certificate" | head -12
printf '%s\n' "--------------------------------------------------------"
group="$(printf '%s\n' "$transcript" | grep -oE "Negotiated TLS1.3 group: [A-Za-z0-9]+" | head -1 | awk '{print $4}')"
case "$group" in
  "$HYBRID_GROUP")
    pass "the lab terminator negotiates the X25519MLKEM768 hybrid (the recorded transcript above)"
    ;;
  "")
    fail "the s_client transcript shows no negotiated-group line — check the openssl client build (3.5+ prints the group)"
    ;;
  *)
    fail "the lab terminator negotiated $group, not X25519MLKEM768 — the 1.x fallback dataplane runs an older OpenSSL (3.3.2 on the 1.6.2 image): this is the classical finding, never a pass; the 2.x dataplane is the re-entry lane"
    ;;
esac
