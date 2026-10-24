package fastpathdifferential

// walls_test.go holds the walls record. The record is the §4.5 wall rows
// table in this package's README.md. The contract cannot join the census
// table tests: it reads a repo-file record, not runtime data, so it
// carries its own test function.
//
// The rules the test holds (the assembly note §4.5 comparison protocol,
// the census record sections 9.5 and 10.7):
//
//   - One row per cell of the section 9.5 table: exactly the two cells,
//     no phantom cell.
//   - Every row reads recorded with its run citation, or PENDING with a
//     named trigger. No third state renders.
//   - No wall figure renders without its run citation (§4.5 rule 6:
//     recorded-run outputs only; never an estimate, never a borrowed
//     figure).
//   - The cite of the §4.5 comparison protocol stays in the record: the
//     protocol owns both walls.

import (
	"os"
	"strings"
	"testing"
)

// wallSectionHeading is the walls record section heading in README.md.
const wallSectionHeading = "## The §4.5 wall rows"

// wallRecordRow is one parsed data row of the walls record table.
type wallRecordRow struct {
	cell    string
	budget  string
	wall    string
	verdict string
}

// TestWallsRecordCarriesCells reads the walls record in README.md and
// holds the contract. A recorded row cites its run. A PENDING row names
// its trigger. A bare figure fails the record.
func TestWallsRecordCarriesCells(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("the walls record: read README.md: %v", err)
	}
	text := string(data)
	start := strings.Index(text, wallSectionHeading)
	if start < 0 {
		t.Fatalf("the walls record: the %q section is missing from README.md; record the two cells with a named trigger per row", wallSectionHeading)
	}
	section := text[start:]
	if next := strings.Index(section[len(wallSectionHeading):], "\n## "); next >= 0 {
		section = section[:len(wallSectionHeading)+next]
	}
	if !strings.Contains(section, "socket-plane-fast-path.md") {
		t.Error("the walls record: the §4.5 comparison protocol is uncited; the record cites the owner of both walls")
	}

	rows := wallRecordRows(section)
	if len(rows) != 2 {
		t.Fatalf("the walls record: %d data rows; the census record section 9.5 pins exactly 2 cells", len(rows))
	}
	wantBudget := map[string]string{
		"Route-mark TC program, per message":       "the §17.1 TC cell",
		"T2/T3 forward share with the route class": "§4.5 rule 4",
	}
	for _, r := range rows {
		want, ok := wantBudget[r.cell]
		if !ok {
			t.Errorf("the walls record: cell %q sits outside the section 9.5 contract", r.cell)
			continue
		}
		if r.budget != want {
			t.Errorf("the walls record: cell %q names budget %q, want %q", r.cell, r.budget, want)
		}
		switch r.verdict {
		case "recorded":
			if !strings.Contains(r.wall, "https://") {
				t.Errorf("the walls record: cell %q reads recorded with no run citation; cite the recorded run (issue, PR body or CI log)", r.cell)
			}
		case "PENDING":
			if !strings.Contains(strings.ToLower(r.wall), "trigger") {
				t.Errorf("the walls record: cell %q reads PENDING without a named trigger", r.cell)
			}
		default:
			t.Errorf("the walls record: cell %q verdict %q; the record reads recorded or PENDING", r.cell, r.verdict)
		}
	}
}

// wallRecordRows parses the walls record table rows. The header and the
// separator rows leave. A well-formed row splits into exactly four cells.
func wallRecordRows(section string) []wallRecordRow {
	var rows []wallRecordRow
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 6 {
			continue
		}
		cells := make([]string, 4)
		for i := 0; i < 4; i++ {
			cells[i] = strings.TrimSpace(parts[i+1])
		}
		if cells[0] == "Cell" || isRowSeparator(cells[0]) {
			continue
		}
		rows = append(rows, wallRecordRow{cell: cells[0], budget: cells[1], wall: cells[2], verdict: cells[3]})
	}
	return rows
}

// isRowSeparator reads a markdown table separator cell.
func isRowSeparator(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '-' && r != ' ' {
			return false
		}
	}
	return true
}
