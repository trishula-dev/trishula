package challenge

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDebugFlowX(t *testing.T) {
	v := NewVerifier([]byte("0123456789abcdef0123456789abcdef"))
	now := time.Now()
	_, ptok, _ := MintProblem(v, 16, now)
	// mimic the page round trip: no loss expected
	body := fmt.Sprintf("problem-token=%s\n", ptok)
	line := ""
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "problem-token=") {
			line = strings.TrimPrefix(l, "problem-token=")
		}
	}
	pr, err := ParseProblem(v, line, now)
	t.Logf("parse err=%v salt=%q diff=%d", err, pr.Salt, pr.Diff)
	ans, tries := SolveProof(pr.Salt, pr.Diff)
	t.Logf("answer=%q tries=%d verify=%v", ans, tries, VerifyProof(pr.Salt, ans, pr.Diff))
}
