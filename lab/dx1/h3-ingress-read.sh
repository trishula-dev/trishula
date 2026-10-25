#!/usr/bin/env bash
# TR-203 L2 (issue #264, leaf L2) — the QUIC-ingress lab topology read.
# The record: docs/design/h3-ingress-posture.md (TR-29). The plan's step 2
# builds the kind/OrbStack topology with an H3 listener on the gateway leg
# speaking h1/h2c upstream. This script reads the topology and runs the two
# topology-leg probes:
#
#   stage 1  the topology leg: the dx1-terminator pod Ready; the Service
#            carries the QUIC (UDP) NodePort row + the https (TCP) row;
#            the dx1-lab-tls fixture Secret sits in the lab ns. The
#            terminator = the NGF dataplane image's nginx build
#            (--with-http_v3_module, measured by `nginx -V` on the image);
#            NGF itself ships no h3 listener row (the compatibility page
#            and the changelog carry none) — the operator owns the
#            topology (the record's N8); the lab terminator answers for
#            the h3 leg (the record's F1 terminator territory).
#   stage 2  probe P4 (the advisory h3spec pass): the pinned h3spec
#            release binary dials the QUIC listener and runs the error
#            case set. The run's transcript = the advisory signal. The
#            tool's output joins no verdict (the record's N5): the gate
#            reads the run's completion, never the tool's case marks.
#   stage 3  the h3 hop of P8: one real HTTP/3 request runs the whole
#            path — the quic-go client (pinned module version, built by
#            this script) → terminator (h3 listener) → h1 upstream →
#            dx1-engine → dx1-echo. The response carries the engine's
#            X-Trishula-Hop marker + the echo body = the same-view rows
#            hold behind the h3 terminator (the record's P8).
#
# Probe P7 (the ban identity) reads the kernel leg, not this script:
#   go test ./test/dosrunner/ -run TestUDPBanIdentityRows -v
# (in-VM, root; the L1 leg's driver. The README carries the row.)
#
# Probes stay advisory lab material: no stage here enters CI, and a
# finding (a case mark, a tool exit) never gates the topology legs.

set -euo pipefail

# the target gate (issue #261): the prereq = docker OR a reachable cluster.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/prereq.sh"

NGF_NS="${NGF_NS:-nginx-gateway}"
TERM_NS="${TERM_NS:-dx1}"
NODE_QUIC_PORT="${NODE_QUIC_PORT:-31440}"
NODE_TERM_TCP_PORT="${NODE_TERM_TCP_PORT:-31441}"
FIXTURE_HOST="${FIXTURE_HOST:-engine.dx1.example.com}"
H3SPEC_VERSION="${H3SPEC_VERSION:-v0.1.14}"
# The pinned release the P4 leg runs; the sha pins the mac arm64 asset the
# leg downloads. h3spec publishes linux x86_64 + mac arm64 builds (no
# linux arm64) — the leg runs from the lab host; other hosts skip with the
# named piece. The tool output joins no verdict (the record's N5).
H3SPEC_URL="https://github.com/kazu-yamamoto/h3spec/releases/download/${H3SPEC_VERSION}/h3spec-mac-arm64"
H3SPEC_SHA256="${H3SPEC_SHA256:-1d76372c74b5fbc28256229e01135f7c878045b8b0a1dc578eaa866e10df140a}"
H3SPEC_CACHE="${H3SPEC_CACHE:-/tmp/tr203-l2-h3spec}"
# The pinned quic-go module the P8 hop's client builds from (no repo dep):
# the script's temp module carries the require row; the build stays off
# the repo's go.mod.
QUICGO_VERSION="${QUICGO_VERSION:-v0.64.1}"
PROBE_BUILD_DIR="${PROBE_BUILD_DIR:-/tmp/tr203-l2-h3probe}"
GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.0}"
export GOTOOLCHAIN

fail() { printf '== H3-INGRESS-READ-FAIL — %s ==\n' "$*" >&2; exit 1; }
pass() { printf 'PASS  %s\n' "$*"; }
stage() { printf '\n== %s ==\n' "$*"; }

# --- stage 1: the topology leg (the gate this script owns) -------------------
stage "stage 1: the QUIC-ingress topology leg (kind/OrbStack; record plan step 2)"

command -v kubectl >/dev/null 2>&1 || fail "missing dependency: kubectl (see lab/README.md and lab/prereq.sh)"

svc_row="$(kubectl -n "${TERM_NS}" get svc dx1-terminator -o jsonpath='{range .spec.ports[*]}{.name}/{.port}/{.nodePort}{"\n"}{end}' 2>/dev/null || true)"
[ -n "${svc_row}" ] || fail "no dx1-terminator Service in ${TERM_NS} — run lab/dx1/setup.sh (the TR-203 L2 topology rows)"
printf 'Service rows:\n%s\n' "${svc_row}"
echo "${svc_row}" | grep -q '^quic/443/[0-9]*$' \
  || fail "the Service carries no quic UDP row — the h3 leg's transport row is absent"
QUIC_NODEPORT="$(echo "${svc_row}" | awk -F/ '$1=="quic"{print $3}')"
[ "${QUIC_NODEPORT}" = "${NODE_QUIC_PORT}" ] \
  || fail "the quic NodePort reads ${QUIC_NODEPORT}, want ${NODE_QUIC_PORT} (the leg's pinned UDP row)"
pass "the quic/443 NodePort row ${NODE_QUIC_PORT}/udp is live"

secret_row="$(kubectl -n "${TERM_NS}" get secret dx1-lab-tls -o name 2>/dev/null || true)"
[ "${secret_row}" = "secret/dx1-lab-tls" ] || fail "the dx1-lab-tls fixture Secret is missing in ${TERM_NS} — setup.sh's TLS leg stage creates it"
pass "the dx1-lab-tls fixture Secret is in place (the DNS + IP SAN pair the dials read)"

pod_row="$(kubectl -n "${TERM_NS}" get pod -l app.kubernetes.io/name=dx1-h3-terminator -o jsonpath='{range .items[*]}{.metadata.name} {.status.phase}{"\n"}{end}' 2>/dev/null || true)"
[ -n "${pod_row}" ] || fail "no dx1-h3-terminator pod exists — run lab/dx1/setup.sh"
case "${pod_row}" in
  *"Running"*) ;;
  *) fail "the terminator pod reads: ${pod_row} — the deployment never went Ready" ;;
esac
printf 'terminator pod: %s\n' "${pod_row}"
pass "the dx1-h3-terminator pod is Running (the nginx build with http_v3_module)"

# --- stage 2: probe P4, the advisory h3spec pass ------------------------------
stage "stage 2: probe P4 — the advisory h3spec pass against the h3 listener"

H3SPEC_BIN=""
for c in "${H3SPEC_BIN_OVERRIDE:-}" "${H3SPEC_CACHE}/h3spec"; do
  [ -n "${c:-}" ] || continue
  if [ -x "$c" ] && shasum -a 256 "$c" 2>/dev/null | awk '{print $1}' | grep -q "${H3SPEC_SHA256}"; then
    H3SPEC_BIN="$c"
    break
  fi
done
if [ -z "${H3SPEC_BIN}" ]; then
  command -v curl >/dev/null 2>&1 || fail "no h3spec binary cached and curl missing — install curl or set H3SPEC_BIN_OVERRIDE"
  mkdir -p "${H3SPEC_CACHE}"
  echo "fetching the pinned h3spec ${H3SPEC_VERSION} (mac arm64) — the sha pins the release"
  curl -sL -o "${H3SPEC_CACHE}/h3spec" "${H3SPEC_URL}"
  chmod +x "${H3SPEC_CACHE}/h3spec" || fail "the h3spec fetch landed a non-executable file"
  got="$(shasum -a 256 "${H3SPEC_CACHE}/h3spec" 2>/dev/null | awk '{print $1}')"
  [ "${got}" = "${H3SPEC_SHA256}" ] || fail "the h3spec asset's sha256 reads ${got}, want ${H3SPEC_SHA256} — refusing to run an unpinned binary"
  H3SPEC_BIN="${H3SPEC_CACHE}/h3spec"
fi

P4_LOG="${H3SPEC_CACHE}/p4-transcript.txt"
set +e
timeout "${H3SPEC_TIMEOUT:-240}" "${H3SPEC_BIN}" 127.0.0.1 "${NODE_QUIC_PORT}" >"${P4_LOG}" 2>&1
P4_EXIT=$?
set -e
rows="$(wc -l < "${P4_LOG}" | tr -d ' ')"
printf 'h3spec %s exit=%s (%s transcript lines at %s)\n\n' "${H3SPEC_VERSION}" "${P4_EXIT}" "${rows}" "${P4_LOG}"
grep -E '\[[✔✘]\]|PENDING' "${P4_LOG}" | head -12 || true
printf '...\n'
tail -2 "${P4_LOG}" || true
[ -s "${P4_LOG}" ] || fail "the h3spec run wrote an empty transcript — no conformance pass happened"
grep -q "examples" "${P4_LOG}" || fail "the h3spec transcript carries no examples summary — the run never completed its case set"
pass "P4 advisory pass recorded: the h3spec case set ran against the live QUIC listener (exit=${P4_EXIT}; the tool output joins no verdict — the record's N5)"

# --- stage 3: the h3 hop of P8, the recorded run -------------------------------
stage "stage 3: probe P8 (the h3 hop) — one real HTTP/3 request through the topology"

command -v go >/dev/null 2>&1 || fail "missing dependency: go (the P8 hop builds the pinned quic-go client; see lab/prereq.sh layer 3)"
go version | head -1

# The probe client: one file, one request, no repo dep. The build pins the
# module row; the hash stamp rebuilds only when the script's client text
# changed (not on a stale cache). The staging dir holds the built source;
# the build dir keeps the binary + the source stamp.
SRC_T="$(mktemp -d /tmp/tr203-l2-p8src.XXXXXX)"
CLIENT_SRC="${SRC_T}/main.go"
cat > "${SRC_T}/go.mod" <<EOF
module tr203l2p8probe

go 1.24

require github.com/quic-go/quic-go ${QUICGO_VERSION}
EOF
cat > "${CLIENT_SRC}" <<'GOEOF'
// probe client: one HTTP/3 request over QUIC (the P8 h3 hop's drive).
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	endpoint := os.Args[1] // host:port of the QUIC listener dial
	sni := os.Args[2]      // the TLS name the lab fixture carries
	path := os.Args[3]     // the request path
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: sni},
	}
	defer tr.Close()
	cl := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", "https://"+endpoint+path, nil)
	if err != nil {
		fmt.Println("REQ-ERR:", err)
		os.Exit(3)
	}
	req.Host = sni
	resp, err := cl.Do(req)
	if err != nil {
		fmt.Println("GET-ERR:", err)
		os.Exit(3)
	}
	defer resp.Body.Close()
	fmt.Println("HTTP3-STATUS:", resp.Status)
	fmt.Println("HTTP3-PROTO:", resp.Proto)
	for _, h := range []string{"X-Trishula-Hop", "Alt-Svc", "X-Powered-By"} {
		if v := resp.Header.Get(h); v != "" {
			fmt.Println("HTTP3-HDR " + h + ": " + v)
		}
	}
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if rerr != nil || len(body) > (1<<20) {
			break
		}
	}
	s := string(body)
	if len(s) > 300 {
		s = s[:300]
	}
	fmt.Println("HTTP3-BODY:", s)
}
GOEOF
CLIENT_SHA="$(shasum -a 256 "${CLIENT_SRC}" | awk '{print $1}')"
H3PROBE_BIN="${PROBE_BUILD_DIR}/h3probe"
trap 'command rm -rf -- "${SRC_T}"' EXIT
if [ ! -x "${H3PROBE_BIN}" ] || [ ! -f "${PROBE_BUILD_DIR}/.stamp" ] \
   || [ "$(cat "${PROBE_BUILD_DIR}/.stamp")" != "${CLIENT_SHA}" ]; then
  echo "building the pinned P8 probe client (quic-go ${QUICGO_VERSION}) in ${PROBE_BUILD_DIR}"
  [ -d "${PROBE_BUILD_DIR}" ] || mkdir -p "${PROBE_BUILD_DIR}"
  (cd "${SRC_T}" && GOTOOLCHAIN="${GOTOOLCHAIN}" go mod tidy && \
     GOTOOLCHAIN="${GOTOOLCHAIN}" go build -o "${H3PROBE_BIN}" .) \
    || fail "the pinned probe client build failed (the build's error above)"
  printf '%s\n' "${CLIENT_SHA}" > "${PROBE_BUILD_DIR}/.stamp"
fi

P8_LOG="$(mktemp /tmp/tr203-l2-p8XXXXXX)"
set +e
"${H3PROBE_BIN}" "127.0.0.1:${NODE_QUIC_PORT}" "${FIXTURE_HOST}" "/tr203-l2-h3-hop" >"${P8_LOG}" 2>&1
P8_EXIT=$?
set -e
printf '%s\n' "---- the h3 hop transcript (client=h3probe quic:${QUICGO_VERSION}; dial 127.0.0.1:${NODE_QUIC_PORT}; SNI ${FIXTURE_HOST}) ----"
cat "${P8_LOG}"
printf '%s\n' "------------------------------------------------------------------------"
[ "${P8_EXIT}" = "0" ] || fail "the h3 GET failed (exit=${P8_EXIT}; transcript above)"
grep -q "^HTTP3-STATUS: 200 OK" "${P8_LOG}" || fail "the h3 hop's status is not 200 (transcript above)"
grep -q "^HTTP3-PROTO: HTTP/3.0" "${P8_LOG}" || fail "the hop did not run over the h3 protocol (transcript above)"
grep -q "^HTTP3-HDR X-Trishula-Hop: engine" "${P8_LOG}" || fail "the response carries no engine hop marker — the request did not traverse the engine upstream leg"
grep -q "^HTTP3-HDR X-Powered-By: HTTP/2 Express (http2-express)" "${P8_LOG}" || fail "the echo pool's marker is missing — the body never reached the demo pool"
pass "P8 h3-hop GREEN: the same-view request runs h3 -> terminator -> h1 upstream -> engine -> echo (the recorded transcript above)"
printf '\nH3-INGRESS-READ-OK\n'
