package main

// TR-34 (issue #34) — the engine TLS-termination secondary mode. The spec's
// §6.3 non-goal carve-out carries the decision: the gateway owns termination
// in the reference deployment and Trishula inspects post-termination
// plaintext; engine-owned termination stays a secondary, feature-gated mode
// (the risk register's R4 mitigation: optional, gateway-owned is the
// default). This file is that gate.
//
// The gate resolves from the --tls-cert/--tls-key pair and is
// all-or-nothing: the pair off = the unchanged plaintext listener; a split
// pair is a boot error, never a half-open listener; the pair set = the
// listener terminates TLS and the unchanged host (the TR-06 proxy, the
// TR-08c consult, the same decision surfaces) serves behind it.
//
// Posture: the listener floor pins TLS 1.2. Upstream re-encryption rides the
// --upstream URL scheme through the unchanged proxy transport — the engine
// opens no second port and grows no new surface. Transport constraints
// (docs/design/socket-plane-fast-path.md sections 3.1 and 3.2): the listener
// is TCP/TLS only — no HTTP/3 surface at this altitude (QUIC terminates in
// userspace and carries no kernel reassembly surface); the engine's HPACK
// behavior and the fast-path legs are untouched (the kernel plane never
// depends on a termination path — §9.1, the shield's tls_seen hint records
// client-side TLS on the wire).

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

// errTLSPair classifies the half-configured gate: cert without key or key
// without cert never opens a listener.
var errTLSPair = errors.New("engine: TLS termination needs both --tls-cert and --tls-key")

// tlsTerminationSpec resolves the gate from the flag pair. Both empty = nil
// (the default: gateway-owned termination, the plaintext listener). Both set
// = the secondary mode's listener spec with the TLS 1.2 floor. Exactly one =
// errTLSPair.
func tlsTerminationSpec(certFile, keyFile string) (*tls.Config, error) {
	switch {
	case certFile == "" && keyFile == "":
		return nil, nil
	case certFile == "" || keyFile == "":
		return nil, errTLSPair
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

// engineListener builds the engine's listening socket per the gate spec.
// nil spec passes the plaintext listener through. An active spec loads the
// cert pair and terminates TLS on the listener — the engine is the TLS
// endpoint; the host behind it is byte-identical (same handler, same
// consult, same decision surfaces). A cert-load failure closes the socket,
// so a bad pair fails at boot, never as a half-open listener.
func engineListener(addr, certFile, keyFile string) (net.Listener, error) {
	cfg, err := tlsTerminationSpec(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("engine: listen %s: %w", addr, err)
	}
	if cfg == nil {
		return ln, nil
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("engine: tls cert load: %w", err)
	}
	cfg.Certificates = []tls.Certificate{pair}
	return tls.NewListener(ln, cfg), nil
}
