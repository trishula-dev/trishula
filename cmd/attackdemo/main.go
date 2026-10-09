package main

// TR-43 (issue #83): the attack demo — two attacks + one enforcement
// kicker, three altitudes of evidence, over MERGED engine code. The full
// run transcript is recorded as comments on issue #83 (validation
// protocol pinned there).
//
// Subcommands:
//
//	crs <request-file>           captured HTTP request through embedded
//	                             Coraza (reference CRS evaluator) → the
//	                             S2 reference verdict (rule ids)
//	bola <objectID> <owner> <subject>   ownership-mismatch decision in
//	                             the §15 verdict.v1 record shape (S3)
//	cel <method> <path> <rate>   the merged TR-02 seed pack (S3, rate rule)
//	ring <pinned-map> <n>        kernel ring events via the merged ingest
//	                             decoder → S0/transport evidence
//	ban <pinned-ban-map> <ip> <secs>   seed a source ban via the TR-03
//	                             loader ABI → TC_ACT_SHOT on replay
//
// Everything here is merged main code except this cmd/ file itself.

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	coraza "github.com/corazawaf/coraza/v3"
	types0 "github.com/corazawaf/coraza/v3/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	tricel "github.com/trishula-dev/trishula/internal/engine/cel"
	triing "github.com/trishula-dev/trishula/internal/engine/ingest"
	trishield "github.com/trishula-dev/trishula/internal/shield"
	"golang.org/x/sys/unix"
)

// crsDirectives: the demo's reference CRS slice — the PL1-class rules the
// payloads match (ids are OWASP CRS 4.x canon; TR-07 embeds the full
// ruleset + the go-ftw differential corpus).
const crsDirectives = `
SecRequestBodyAccess Off
SecResponseBodyAccess Off
SecDefaultAction "phase:1,log,pass"
SecRule REQUEST_URI "@contains /etc/passwd" "id:930120,phase:1,log,msg:'OS File Access Attempt',severity:CRITICAL"
SecRule REQUEST_URI "@rx \.\./" "id:930100,phase:1,log,msg:'Path Traversal Attack (/../)',severity:CRITICAL"
SecRule REQUEST_URI "@contains union%20select" "id:942140,phase:1,log,msg:'SQL Injection Attack',severity:CRITICAL"
`

func runCRS(reqFile string) error {
	body, err := os.ReadFile(reqFile)
	if err != nil {
		return err
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(crsDirectives))
	if err != nil {
		return fmt.Errorf("coraza init: %w", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()

	head := body
	rest := []byte(nil)
	if i := bytes.Index(body, []byte("\r\n\r\n")); i >= 0 {
		head, rest = body[:i], body[i+4:]
	} else if i := bytes.Index(body, []byte("\n\n")); i >= 0 {
		head, rest = body[:i], body[i+2:]
	}
	rawLines := bytes.Split(head, []byte("\n"))
	reqLine := strings.TrimSpace(string(rawLines[0]))
	var method, uri, proto string
	parts := strings.Fields(reqLine)
	if len(parts) >= 3 {
		method, uri, proto = parts[0], parts[1], parts[2]
	} else if len(parts) == 2 {
		method, uri = parts[0], parts[1]
	} else {
		return fmt.Errorf("unparsable request line %q", reqLine)
	}
	_ = proto
	_ = waf
	tx.ProcessURI(uri, method, proto)
	tx.SetServerName("demo.internal")
	var interrupt *types0.Interruption
	for _, hl := range rawLines[1:] {
		if i := bytes.IndexByte(hl, ':'); i > 0 {
			tx.AddRequestHeader(string(bytes.TrimSpace(hl[:i])),
				string(bytes.TrimSpace(hl[i+1:])))
		}
	}
	interrupt = tx.ProcessRequestHeaders()
	if interrupt == nil && len(rest) > 0 {
		_, _, werr := tx.WriteRequestBody(rest)
		if werr == nil {
			interrupt, _ = tx.ProcessRequestBody()
		}
	}
	for _, res := range tx.MatchedRules() {
		fmt.Printf("crs:      rule=%d sev=%s msg=%q\n",
			res.Rule().ID(), res.Rule().Severity().String(), res.Message())
	}
	if interrupt != nil {
		fmt.Printf("crs:      → INTERRUPT status=%d (the S2 slot would block)\n", interrupt.Status)
	} else {
		fmt.Printf("crs:      → pass\n")
	}
	return nil
}

// bolaSub: the ownership-mismatch decision for the §15 verdict record
// demo. subject/owner stand in for the AUTHZ state the engine's view
// carries once TR-05's view extension lands.
func bolaSub(objectID, owner, subject string) {
	match := subject == owner
	verdict := map[bool]string{true: "AUTHORIZED", false: "BLOCK (API1:2023 BOLA)"}[match]
	fmt.Printf("bola:     object=%s owner=%s subject=%s → %s\n", objectID, owner, subject, verdict)
	fmt.Printf("          verdict.v1: {route:\"/api/v1/orders/:id\", rule:\"auth.ownership_match\", "+
		"action:%q, decision:%t, evidence:{owner:%q, subject:%q}}\n",
		map[bool]string{true: "allow", false: "block"}[match], match, owner, subject)
}

func celRate(method, path string, rate int) error {
	pack, err := tricel.LoadRulePack("rules/cel/seed.yaml")
	if err != nil {
		return err
	}
	v, err := pack.Rules[0].Eval(tricel.Request{
		Method:      method,
		Path:        path,
		RateWindows: map[string]tricel.RateWindow{"5m": {Requests: int64(rate)}},
	})
	fmt.Printf("cel:      %s %s rate=%d/5m → match=%v cost=%d\n",
		method, path, rate, v.Match, v.Cost)
	return err
}

func runRing(pin string, n int) error {
	m, err := ebpf.LoadPinnedMap(pin, nil)
	if err != nil {
		return err
	}
	defer m.Close()
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return err
	}
	defer rd.Close()
	for i := 0; i < n; i++ {
		rec, err := rd.Read()
		if err != nil {
			return nil
		}
		ev, derr := triing.DecodeFlowEvent(rec.RawSample)
		if derr != nil {
			continue
		}
		fmt.Printf("kernel:   src=%v flags=%02x dport=%d payload=%dB path=%q\n",
			ev.SrcIP4, ev.TCPFlags, ev.DstPort, ev.PayloadLen, ev.PathString())
	}
	return nil
}

// runBan seeds one source ban via the TR-03 loader ABI (cilium Put with
// the wire structs pinned in shield contract tests).
func runBan(pin, ipStr string, seconds int) error {
	m, err := ebpf.LoadPinnedMap(pin, nil)
	if err != nil {
		return err
	}
	defer m.Close()
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return err
	}
	key := trishield.BanKeyFromIP(ip, trishield.KeyClassIP)
	until := nowMonoNS() + uint64(seconds)*1e9
	val := trishield.BanVal{UntilTS: until, Tier: 1, ReasonCode: 4211}
	if err := m.Put(&key, &val); err != nil {
		return err
	}
	fmt.Printf("ban:      src=%s tier=1 reason=4211 until=mono+%ds → kernel drops on next packet (TC_ACT_SHOT)\n", ipStr, seconds)
	return nil
}

func nowMonoNS() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: attackdemo crs|bola|cel|ring|ban ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "crs":
		err = runCRS(os.Args[2])
	case "bola":
		bolaSub(os.Args[2], os.Args[3], os.Args[4])
	case "cel":
		rate, _ := strconv.Atoi(os.Args[4])
		err = celRate(os.Args[2], os.Args[3], rate)
	case "ring":
		n, _ := strconv.Atoi(os.Args[3])
		err = runRing(os.Args[2], n)
	case "ban":
		secs, _ := strconv.Atoi(os.Args[4])
		err = runBan(os.Args[2], os.Args[3], secs)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
