//go:build linux

package fastpathdifferential

// TR-40d (issue #190, child of TR-40 #52): the kernel-gated leg of the
// shadow differential. The test loads the committed route-mark object per
// corpus case the way the real attach path does (routetemplate.Instantiate
// over the compiled bundle), then drives the program with the same frame
// bytes the userspace projection parsed (BPF_PROG_TEST_RUN over the TC
// program). Fidelity is the gate: the kernel return value and the userspace
// decision must name the same outcome for every frame.
//
// The kernel gate mirrors the route-posture e2e files (test/route-e2e):
// root on Linux, BTF present. No netns and no attach ride this proof —
// the program runs in the test-run harness, it never attaches to live
// traffic here. FASTPATH_DIFF_E2E_REQUIRED=1 (the CI step of a follow-up
// gate job) turns every environment skip into a failure, so a job that
// cannot run the leg never reads green.
//
//	sudo env PATH="$PATH" HOME="$HOME" FASTPATH_DIFF_E2E_REQUIRED=1 \
//	  go test -tags fastpath_diff_e2e -v ./test/fastpath-differential/
//
// Test-run boundary, recorded honestly: the run surface returns the TC
// action only. The skb mark the template writes does not read back on
// this surface, so the kernel leg scores the decision outcome; the row-id
// leg stays a userspace-model pin (the census record section 10 carries
// the boundary).

import (
	"os"
	"testing"

	routetemplate "github.com/trishula-dev/trishula/internal/fastpath/routetemplate"
)

// mustKernel gates the kernel facilities. FASTPATH_DIFF_E2E_REQUIRED=1
// turns every skip into a failure, so the gate never reads green
// vacuously.
func mustKernel(t *testing.T) {
	t.Helper()
	required := os.Getenv("FASTPATH_DIFF_E2E_REQUIRED") != ""
	if os.Geteuid() != 0 {
		if required {
			t.Fatal("FASTPATH_DIFF_E2E_REQUIRED: the kernel leg needs root")
		}
		t.Skip("the kernel-leg fidelity proof needs root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		if required {
			t.Fatalf("FASTPATH_DIFF_E2E_REQUIRED: no BTF at /sys/kernel/btf/vmlinux: %v", err)
		}
		t.Skip("no BTF at /sys/kernel/btf/vmlinux")
	}
}

// TestKernelDecisionStream runs the kernel decision stream over the whole
// corpus: load, drive the frame, read the TC action, compare the
// userspace projection and the pinned expectation. The census lines carry
// the run for the record; a delta names the case and both reads verbatim.
func TestKernelDecisionStream(t *testing.T) {
	mustKernel(t)
	corpus, err := LoadCorpus()
	if err != nil {
		t.Fatalf("corpus load: %v", err)
	}

	live := map[string]int{}
	ran, fidelity, deltas := 0, 0, 0
	for _, c := range corpus.Cases {
		if c.Skipped {
			continue
		}
		stream, err := CompileCase(c)
		if err != nil {
			t.Fatalf("compile case %s: %v", c.Name, err)
		}
		coll, err := routetemplate.Instantiate(stream.Bundle)
		if err != nil {
			t.Fatalf("instantiate case %s (verifier): %v", c.Name, err)
		}
		prog, ok := coll.Programs["route_mark"]
		if !ok || prog == nil {
			coll.Close()
			t.Fatalf("the loaded collection misses route_mark (case %s): %v", c.Name, coll.Programs)
		}
		frame := BuildFrame(c.Frame)
		model := TemplateDecision(stream.Rows, frame)
		retval, _, err := prog.Test(frame)
		coll.Close()
		if err != nil {
			t.Fatalf("test run case %s: %v", c.Name, err)
		}
		kernelDrop := retval == tcActShot

		ran++
		if kernelDrop != model.Drop {
			// Fidelity delta: the budget row counts it.
			live["kernel-fidelity"]++
			deltas++
			t.Errorf("kernel delta: case %s: kernel %s, userspace projection %s",
				c.Name, actionWord(retval), decisionWord(model.Drop))
			continue
		}
		// Fidelity holds; the pinned outcome still reads on the kernel
		// leg (the same corpus the kernel-free gate pins). The mark and
		// the row id stay userspace-leg reads: the test-run surface
		// returns the TC action only.
		if kernelDrop != (c.Expect.Outcome == OutcomeDrop) {
			deltas++
			t.Errorf("kernel delta: case %s: kernel %s, corpus expects %s",
				c.Name, actionWord(retval), c.Expect.Outcome)
			continue
		}
		fidelity++
	}

	t.Logf("fastpath-differential kernel census: frames %d, fidelity %d/%d, deltas %d",
		ran, fidelity, ran, deltas)
	for _, v := range VerifyBudgets(live) {
		if v.Class != "kernel-fidelity" {
			// The kernel leg scores its own class only; the corpus census
			// rows read on the kernel-free gate.
			continue
		}
		t.Logf("fastpath-differential budget row %s: live %d, %s", v.Class, v.Live, v.Detail)
		if !v.Holds {
			t.Errorf("budget row %s: %s", v.Class, v.Detail)
		}
	}
	if deltas > 0 {
		t.Fatalf("kernel fidelity carries %d deltas", deltas)
	}
}

// actionWord names the TC action a run returned.
func actionWord(code uint32) string {
	if code == tcActShot {
		return "drop (TC_ACT_SHOT)"
	}
	return "forward (TC_ACT_OK)"
}

// decisionWord names the userspace projection's outcome.
func decisionWord(drop bool) string {
	if drop {
		return "drop (TC_ACT_SHOT wanted)"
	}
	return "forward (TC_ACT_OK wanted)"
}
