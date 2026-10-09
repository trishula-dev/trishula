// cmd/trishula is the PRD §19 skeleton entrypoint (TR-02): today it proves
// the seed rule path end-to-end via --selftest; serving modes arrive with
// the engine/shield/operator builds (TR-03+).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	tricel "github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

const usage = `trishula — eBPF-native WAF/API firewall (skeleton)

Modes (TR-02):
  --selftest            evaluate the seed CEL rule pack against a sample
                        request fixture and print per-case verdicts
  --parity              walk the S0+S3 ladder slice over the parity fixture
                        matrix and print the verdict log per case (TR-05d)
Flags:
  --rules <path>        rule-pack YAML (default: rules/cel/seed.yaml)
  --requests <path>     sample-request fixture YAML
                        (default: internal/engine/cel/testdata/sample_request.yaml)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

// run executes one skeleton mode; args/args-stdout are injected for tests.
func run(args []string, stdout io.Writer) int {
	// Private FlagSet (never flag.CommandLine): the testing package owns
	// the process-wide CommandLine, so binding to it redefines flags on
	// every run() call inside tests. ContinueOnError prints parse failures
	// to stderr on its own.
	fs := flag.NewFlagSet("trishula", flag.ContinueOnError)
	selftest := fs.Bool("selftest", false, "evaluate the seed rule pack against the sample fixture")
	parity := fs.Bool("parity", false, "walk the S0+S3 parity matrix and print the verdict log")
	rules := fs.String("rules", "rules/cel/seed.yaml", "rule-pack YAML path")
	requests := fs.String("requests", "internal/engine/cel/testdata/sample_request.yaml", "sample-request fixture path")
	if err := fs.Parse(args); err != nil {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch {
	case *parity:
		return parityRun(*rules, stdout)
	case *selftest:
		if code := selftestRun(*rules, *requests, stdout); code != 0 {
			return code
		}
		fmt.Fprintln(stdout, "selftest OK")
		return 0
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
}

// selftestRun loads the pack + fixture and evaluates every case, printing
// one verdict line per case. Returns nonzero on any load/eval failure or
// unexpected verdict (the fixture's own error-expectation cases count as
// success when they error as expected).
func selftestRun(rulesPath, requestsPath string, stdout io.Writer) int {
	pack, err := tricel.LoadRulePack(rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "selftest: load %s: %v\n", rulesPath, err)
		return 1
	}
	rules := pack.Rules
	if len(rules) == 0 {
		fmt.Fprintln(os.Stderr, "selftest: empty rule pack")
		return 1
	}
	if len(rules) > 1 {
		fmt.Fprintf(os.Stderr, "selftest: seed pack must hold exactly one rule (TR-02), got %d\n", len(rules))
		return 1
	}
	data, err := os.ReadFile(requestsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "selftest: read %s: %v\n", requestsPath, err)
		return 1
	}
	cases, err := tricel.ParseRequestCases(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "selftest: parse %s: %v\n", requestsPath, err)
		return 1
	}
	failed := false
	for _, tc := range cases {
		v, evalErr := rules[0].Eval(tc.Request)
		status := "PASS"
		switch {
		case (evalErr != nil) != tc.Expected.Error:
			status = "FAIL"
			failed = true
		case !tc.Expected.Error && v.Match != tc.Expected.Match:
			status = "FAIL"
			failed = true
		}
		detail := ""
		if v.Detail != "" {
			detail = " detail=" + v.Detail
		}
		fmt.Fprintf(stdout, "case %-36s match=%-5v error=%-5v cost=%-5d %s%s\n",
			tc.Name, v.Match, v.Error, v.Cost, status, detail)
	}
	if failed {
		return 1
	}
	return 0
}

// parityRun walks the S0+S3 fixture matrix (TR-05d) and prints the verdict
// log — the same matrix the ladder package's TestParityWalk asserts, so
// the CLI surfaces the parity evidence an operator can run by hand. Exit
// 0 iff every case resolved as the matrix documents.
func parityRun(rulesPath string, stdout io.Writer) int {
	pack, err := tricel.LoadRulePack(rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parity: load %s: %v\n", rulesPath, err)
		return 1
	}
	out, code := ladder.ParityMatrixRender(pack)
	fmt.Fprint(stdout, out)
	return code
}
