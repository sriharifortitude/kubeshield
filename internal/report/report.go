// Package report renders a scan's results as terminal text, JSON, or
// SARIF 2.1.0 (for GitHub code scanning and similar).
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sriharifortitude/kubeshield/internal/rules"
	"github.com/sriharifortitude/kubeshield/internal/waiver"
)

// Row is one finding plus whatever a waiver file did to it.
type Row struct {
	rules.Finding
	WaiverOutcome waiver.Outcome
	Waiver        *waiver.Entry
}

// Result is a whole scan: every row, in a stable order (by file, then
// resource, then rule), so a re-run over the same manifests produces a
// byte-identical report.
type Result struct {
	Rows []Row
}

func NewResult(rows []Row) Result {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.RuleID < b.RuleID
	})
	return Result{Rows: rows}
}

// Counts by what actually happened: a waived finding is not "clean" and
// is not "failing" -- it is its own thing, visible in every format.
type Counts struct {
	Fail          int `json:"fail"`
	Waived        int `json:"waived"`
	ExpiredWaiver int `json:"expired_waiver"`
}

func (r Result) Counts() Counts {
	var c Counts
	for _, row := range r.Rows {
		switch row.WaiverOutcome {
		case waiver.Expired:
			c.ExpiredWaiver++
		case waiver.Waived:
			c.Waived++
		default:
			c.Fail++
		}
	}
	return c
}

// Failing returns the rows that count against --fail-on: real findings
// and expired waivers, at or above the threshold severity.
func (r Result) Failing(threshold rules.Severity) []Row {
	var out []Row
	for _, row := range r.Rows {
		if row.WaiverOutcome == waiver.Waived {
			continue
		}
		if !row.Severity.AtLeast(threshold) {
			continue
		}
		out = append(out, row)
	}
	return out
}

func Terminal(r Result) string {
	var b strings.Builder
	for _, row := range r.Rows {
		label := statusLabel(row)
		loc := resourceLocation(row.Finding)
		fmt.Fprintf(&b, "%-13s %-30s %-8s %s\n", label, loc, row.Severity, row.Message)
		if row.Remediation != "" && row.WaiverOutcome != waiver.Waived {
			fmt.Fprintf(&b, "              fix: %s\n", row.Remediation)
		}
		if row.Waiver != nil {
			verb := "waived"
			if row.WaiverOutcome == waiver.Expired {
				verb = "WAIVER EXPIRED"
			}
			fmt.Fprintf(&b, "              %s %s: %s\n", verb, row.Waiver.Expires, row.Waiver.Reason)
		}
	}
	c := r.Counts()
	fmt.Fprintf(&b, "\n%d findings: %d failing, %d waived, %d expired waivers\n",
		len(r.Rows), c.Fail, c.Waived, c.ExpiredWaiver)
	return b.String()
}

func resourceLocation(f rules.Finding) string {
	loc := f.Kind + "/" + f.Name
	if f.Namespace != "" {
		loc = f.Namespace + "/" + loc
	}
	if f.Container != "" {
		loc += " (" + f.Container + ")"
	}
	return loc
}

func statusLabel(row Row) string {
	switch row.WaiverOutcome {
	case waiver.Expired:
		return "EXPIRED"
	case waiver.Waived:
		return "waived"
	default:
		return "FAIL"
	}
}

type jsonRow struct {
	Rule        string  `json:"rule"`
	Severity    string  `json:"severity"`
	File        string  `json:"file"`
	Kind        string  `json:"kind"`
	Namespace   string  `json:"namespace,omitempty"`
	Name        string  `json:"name"`
	Container   string  `json:"container,omitempty"`
	Message     string  `json:"message"`
	Remediation string  `json:"remediation,omitempty"`
	Waived      bool    `json:"waived"`
	WaiverNote  *string `json:"waiver_note,omitempty"`
}

func JSON(r Result) ([]byte, error) {
	rows := make([]jsonRow, 0, len(r.Rows))
	for _, row := range r.Rows {
		jr := jsonRow{
			Rule: row.RuleID, Severity: string(row.Severity), File: row.File,
			Kind: row.Kind, Namespace: row.Namespace, Name: row.Name, Container: row.Container,
			Message: row.Message, Remediation: row.Remediation,
			Waived: row.WaiverOutcome == waiver.Waived,
		}
		if row.Waiver != nil {
			note := row.Waiver.Reason + " (expires " + row.Waiver.Expires + ")"
			jr.WaiverNote = &note
		}
		rows = append(rows, jr)
	}
	c := r.Counts()
	out := struct {
		Summary Counts    `json:"summary"`
		Rows    []jsonRow `json:"findings"`
	}{c, rows}
	return json.MarshalIndent(out, "", "  ")
}
