//go:build linux && shield_hook_spike

// TR-205 lane C (issue #292) — the shield hook spike probe.
//
// The probe loads the four committed shield hook objects on the running
// kernel, one collection per hook class, and records one load state per
// hook. It reads the committed bpf2go release objects (the artifacts the
// multiarch census guards) and drives them through github.com/cilium/ebpf
// — the same load library the production loaders use.
//
// The probe creates no pins. Every collection closes before exit, so the
// probe leaves no kernel residue.
//
// Each row records the object sha256 and size. A stale object pair reads
// about 3x the stripped size; the fingerprint catches that on the receipt.
//
// Usage: spike <repo-root> <out-dir>
//
// Exit codes: 0 — the spike recorded at least one load state (a per-hook
// FAIL row is a recorded result, not an error); 2 — the kernel environment
// lacks root or BTF, so no evidence exists; 3 — zero hook classes loaded,
// a kernel environment anomaly.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// hookRow pins one shield hook class: the program entrypoint, its SEC
// altitude, the C source, and the committed x86 release object.
type hookRow struct {
	program string
	attach  string
	source  string
	object  string
}

// hooks is the spike inventory. The x86 object per hook matches the runner
// arm; the census guard pairs every x86 object with its arm64 twin.
var hooks = []hookRow{
	{program: "shield_xdp", attach: "xdp", source: "bpf/shield_xdp.c", object: "internal/shield/bpf_shield_x86_bpfel.o"},
	{program: "ban_xdp", attach: "xdp", source: "bpf/ban_xdp.c", object: "test/banenforce/ban_enforce_x86_bpfel.o"},
	{program: "tc_ingress_waf", attach: "tc", source: "bpf/flow_tc.c", object: "internal/engine/ingest/ingest_flow_x86_bpfel.o"},
	{program: "route_mark", attach: "tc", source: "bpf/route_mark.c", object: "internal/fastpath/routetemplate/route_mark_x86_bpfel.o"},
}

// hookResult carries one hook's recorded load state and evidence.
type hookResult struct {
	row      hookRow
	state    string // LOADED or FAIL(step)
	sizeB    int64
	sha      string // short sha256 fingerprint
	maps     []string
	progOK   bool
	firstErr string // one error line, truncated (the table cell)
	fullErr  string // every byte of the error (the artifact)
}

// errCut caps a table-cell error line (the full error stays verbatim in
// the txt record).
const errCut = 96

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: spike <repo-root> <out-dir>")
		os.Exit(2)
	}
	repo, out := os.Args[1], os.Args[2]

	// The environment gates: root + BTF. Without them no load verdict is
	// recordable, so the probe reports and stops (exit 2).
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "spike: not root; rerun inside the privileged pod (the BPF load caps are root-only)")
		os.Exit(2)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		fmt.Fprintln(os.Stderr, "spike: no /sys/kernel/btf/vmlinux; this kernel cannot record a CO-RE load verdict")
		os.Exit(2)
	}

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		fmt.Fprintf(os.Stderr, "spike: uname: %v\n", err)
		os.Exit(2)
	}
	sysname := cstr(uts.Sysname[:])
	release := cstr(uts.Release[:])
	version := cstr(uts.Version[:])

	runnerImage := os.Getenv("SPIKE_RUNNER_IMAGE")
	podDigest := readFirstLine(filepath.Join(out, "docker-digest.txt"))

	results := make([]hookResult, 0, len(hooks))
	for _, h := range hooks {
		results = append(results, loadOne(h, repo))
	}

	loaded := 0
	for _, r := range results {
		if r.state == stateLoaded {
			loaded++
		}
	}

	md := renderMD(sysname, release, version, runnerImage, podDigest, results, loaded, len(hooks))
	txt := renderTXT(sysname, release, version, runnerImage, podDigest, results, loaded, len(hooks), repo, out)

	if err := os.WriteFile(filepath.Join(out, "spike-loads.md"), []byte(md), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "spike: write spike-loads.md: %v\n", err)
		os.Exit(2)
	}
	if err := os.WriteFile(filepath.Join(out, "spike-loads.txt"), []byte(txt), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "spike: write spike-loads.txt: %v\n", err)
		os.Exit(2)
	}
	fmt.Print(md)
	fmt.Printf("\nspike summary: %d of %d hook classes loaded; the verbatim record sits in spike-loads.txt\n", loaded, len(hooks))

	// Zero loaded states = the kernel environment carries an anomaly
	// (module, caps or BTF loss). The run still recorded its evidence; the
	// red exit keeps one loud signal for that case.
	if loaded == 0 {
		os.Exit(3)
	}
}

// loadOne loads one hook's committed object and records the state per the
// step that failed (spec, collection load, or the named program check).
func loadOne(h hookRow, repo string) hookResult {
	res := hookResult{row: h, state: stateLoaded}
	objPath := filepath.Join(repo, h.object)

	st, err := os.Stat(objPath)
	if err != nil {
		res.state = stateFailObject
		res.fullErr = err.Error()
		res.firstErr = cutLine(err.Error())
		return res
	}
	res.sizeB = st.Size()
	data, err := os.ReadFile(objPath)
	if err != nil {
		res.state = stateFailObject
		res.fullErr = err.Error()
		res.firstErr = cutLine(err.Error())
		return res
	}
	sum := sha256.Sum256(data)
	res.sha = hex.EncodeToString(sum[:])[:12]

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		res.state = stateFailSpec
		res.fullErr = err.Error()
		res.firstErr = cutLine(err.Error())
		return res
	}
	for name := range spec.Maps {
		res.maps = append(res.maps, name)
	}
	sort.Strings(res.maps)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		res.state = stateFailCollection
		res.fullErr = err.Error()
		res.firstErr = cutLine(err.Error())
		return res
	}
	// The named-program check (never a positional pick): the collection
	// must carry the hook's entrypoint by name.
	if _, ok := coll.Programs[h.program]; !ok {
		res.state = stateFailProgram
		res.fullErr = fmt.Sprintf("collection holds no program %q (found: %v)", h.program, progNames(coll))
		coll.Close()
		return res
	}
	res.progOK = true
	res.fullErr = ""
	res.firstErr = ""
	coll.Close()
	return res
}

// state vocabulary (the table cells and the txt record share it).
const (
	stateLoaded         = "LOADED"
	stateFailObject     = "FAIL(object missing)"
	stateFailSpec       = "FAIL(spec load)"
	stateFailCollection = "FAIL(collection load)"
	stateFailProgram    = "FAIL(program name absent)"
)

func progNames(coll *ebpf.Collection) []string {
	names := make([]string, 0, len(coll.Programs))
	for name := range coll.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// cutLine keeps the first line of a multi-line error and truncates it.
func cutLine(s string) string {
	line := strings.SplitN(s, "\n", 2)[0]
	line = strings.TrimSpace(line)
	r := []rune(line)
	if len(r) > errCut {
		return string(r[:errCut]) + "…"
	}
	return line
}

// escapeCell makes one markdown table cell safe: a raw pipe splits the
// column and a backtick breaks the code span.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	return strings.ReplaceAll(s, "|", "\\|")
}

func readFirstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
}

// cstr renders a fixed integer array's NUL-terminated prefix. The element
// type varies by GOOS (int8 on linux, uint8 elsewhere), so the helper is
// generic over both.
func cstr[T ~int8 | ~uint8](b []T) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

const mdHeader = `<!-- generated by cmd/shield-hook-spike under -tags shield_hook_spike; do not edit by hand -->
`

// renderMD draws the job-summary section: the per-hook table, the full
// verbatim errors in collapsed blocks, and the pinned-recommendation
// fields issue #292 cites.
func renderMD(sysname, release, version, runnerImage, podDigest string, results []hookResult, loaded, total int) string {
	var b strings.Builder
	b.WriteString(mdHeader)
	b.WriteString("\n## Shield hook spike — per-hook load state\n\n")

	b.WriteString("| hook (program) | attach type | source | committed object | load state | load error (first line, truncated) | min kernel features | notes |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, r := range results {
		state := "`" + r.state + "`"
		errCell := "(none)"
		mfc := "none (loaded)"
		if r.state != stateLoaded {
			// A table cell breaks on a raw pipe or backtick, so the
			// verbatim error cell escapes both (the details block and
			// the txt record keep the unescaped bytes).
			errCell = "`" + escapeCell(r.firstErr) + "`"
			// The min-features cell stays PENDING here on purpose: the
			// post-run fill (issue #292) sets it per FAIL row.
			mfc = "PENDING (issue #292 fill)"
		}
		detail := fmt.Sprintf("`%s` %d B; %d maps", r.sha, r.sizeB, len(r.maps))
		if r.progOK {
			detail += "; program `" + r.row.program + "` loaded"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s | %s | %s | %s |\n",
			r.row.program, r.row.attach, r.row.source, r.row.object, state, errCell, mfc, detail)
	}
	b.WriteString(fmt.Sprintf("\nRecorded verdicts: %d of %d hook classes loaded.\n", loaded, total))
	b.WriteString("\nA `FAIL` row is a recorded result for issue #292, not a probe defect. The verbatim record sits in the `shield-hook-spike` artifact.\n")

	for _, r := range results {
		if r.state == stateLoaded {
			continue
		}
		fmt.Fprintf(&b, "\n<details>\n<summary>hook `%s` — the full load error (verbatim)</summary>\n\n```text\n%s\n```\n\n</details>\n", r.row.program, r.fullErr)
	}

	b.WriteString("\n## Pinned-recommendation fields (issue #292)\n\n")
	b.WriteString("| field | recorded value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| kernel class | `%s` |\n", sysname))
	b.WriteString(fmt.Sprintf("| kernel release | `%s` |\n", release))
	b.WriteString(fmt.Sprintf("| kernel version (full) | `%s` |\n", version))
	ri := runnerImage
	if ri == "" {
		ri = "(not passed)"
	}
	b.WriteString(fmt.Sprintf("| runner image tag | `%s` |\n", ri))
	b.WriteString("| pod image | `ubuntu:24.04` |\n")
	if podDigest != "" {
		b.WriteString(fmt.Sprintf("| pod image digest | `%s` |\n", podDigest))
	}
	b.WriteString(fmt.Sprintf("| go toolchain | `%s` |\n", runtime.Version()))
	return b.String()
}

// renderTXT draws the verbatim record: one environment block, then one
// evidence block per hook, with no truncation anywhere.
func renderTXT(sysname, release, version, runnerImage, podDigest string, results []hookResult, loaded, total int, repo, out string) string {
	var b strings.Builder
	b.WriteString("shield-hook-spike — the verbatim record (cmd/shield-hook-spike)\n")
	b.WriteString("====================================================================\n")
	fmt.Fprintf(&b, "kernel sysname        : %s\n", sysname)
	fmt.Fprintf(&b, "kernel release        : %s\n", release)
	fmt.Fprintf(&b, "kernel version        : %s\n", version)
	fmt.Fprintf(&b, "runner image tag      : %s\n", orUnset(runnerImage))
	fmt.Fprintf(&b, "pod image             : ubuntu:24.04\n")
	fmt.Fprintf(&b, "pod image digest      : %s\n", orUnset(podDigest))
	fmt.Fprintf(&b, "go toolchain          : %s\n", runtime.Version())
	fmt.Fprintf(&b, "object root           : %s (arg 1)\n", repo)
	fmt.Fprintf(&b, "out dir               : %s (arg 2)\n", out)
	fmt.Fprintf(&b, "btf                   : /sys/kernel/btf/vmlinux (stat ok)\n")
	fmt.Fprintf(&b, "pins created          : none (every collection closes before exit)\n")
	fmt.Fprintf(&b, "exit policy           : FAIL rows are results; exit 3 only on zero hooks loaded\n")
	b.WriteString("\n")
	for _, r := range results {
		fmt.Fprintf(&b, "hook %s (%s) — object %s\n", r.row.program, r.row.attach, r.row.object)
		fmt.Fprintf(&b, "  from source         : %s\n", r.row.source)
		fmt.Fprintf(&b, "  sha256 (short)      : %s\n", orUnset(r.sha))
		fmt.Fprintf(&b, "  size                : %d B\n", r.sizeB)
		fmt.Fprintf(&b, "  maps                : %s\n", orUnset(strings.Join(r.maps, ", ")))
		fmt.Fprintf(&b, "  state               : %s\n", r.state)
		fmt.Fprintf(&b, "  program check       : %s\n", progCheckLine(r))
		if r.fullErr != "" {
			fmt.Fprintf(&b, "  error (verbatim):\n")
			for _, line := range strings.Split(strings.TrimRight(r.fullErr, "\n"), "\n") {
				fmt.Fprintf(&b, "    %s\n", line)
			}
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "spike summary: %d of %d hook classes loaded; the fill owner is issue #292\n", loaded, total)
	return b.String()
}

func progCheckLine(r hookResult) string {
	if r.progOK {
		return "program " + r.row.program + " loaded (selected by name)"
	}
	return "program " + r.row.program + " absent (selected by name)"
}

func orUnset(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}
