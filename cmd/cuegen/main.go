// Command cuegen regenerates the TR-46 derived artefacts from the CUE
// definitions (cue/): the seed pack copies, the ban-conformance fixtures
// and the deployment/dx1/manifests tree. It runs from any directory inside
// the repo; the module root is discovered upward.
//
// The cue-gate workflow (.github/workflows/cue-gate.yml) runs this command
// before its golden-diff step: any diff means a derived artefact drifted
// from its definition, and a hand edit to a derived artefact fails the gate.
package main

import (
	"fmt"
	"os"

	"github.com/trishula-dev/trishula/internal/cuegen"
)

func main() {
	if err := cuegen.Run("."); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
