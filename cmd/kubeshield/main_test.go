package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// out runs the CLI in-process and returns the exit code plus whatever
// was written to --output. --output is inserted right after the
// subcommand: flag parsing stops at the first non-flag token, so it must
// come before the positional path argument.
func out(t *testing.T, args ...string) (code int, report string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "report.out")
	withOutput := append([]string{args[0], "--output", path}, args[1:]...)
	code = run(withOutput)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return code, ""
		}
		t.Fatalf("reading report: %s", err)
	}
	return code, string(data)
}

func TestScanTheSmallFixtureWithoutWaivers(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "../../testdata/small.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(report, `"fail": 7`) {
		t.Errorf("report:\n%s", report)
	}
	for _, want := range []string{
		`"rule": "privileged-container"`,
		`"rule": "rbac-wildcard"`,
		`"rule": "host-namespace"`,
		`"name": "web"`,
		`"name": "everything"`,
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %s\n%s", want, report)
		}
	}
	if strings.Contains(report, `"name": "api"`) {
		t.Error("the clean api Deployment should produce no findings")
	}
}

func TestScanTheSmallFixtureWithWaivers(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "--waivers", "../../testdata/waivers.yaml", "../../testdata/small.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the expired waiver still fails the gate)", code)
	}
	if !strings.Contains(report, `"fail": 5`) || !strings.Contains(report, `"waived": 1`) {
		t.Errorf("report:\n%s", report)
	}
	if !strings.Contains(report, "migration ticket JIRA-1") {
		t.Error("the active waiver's reason should be in the report")
	}
	if !strings.Contains(report, "was meant to be temporary") {
		t.Error("the expired waiver's reason should still be visible")
	}
}

func TestScanWithAHighFailOnThresholdDropsTheMediumFindings(t *testing.T) {
	// with waivers applied, the two remaining Critical findings (rbac
	// wildcard, the expired host-namespace waiver) still fail at
	// --fail-on critical; the Mediums on web/app do not count.
	code, _ := out(t, "scan", "--fail-on", "critical", "--waivers", "../../testdata/waivers.yaml", "../../testdata/small.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestScanTheCleanFixtureExitsZero(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "../../testdata/clean.yaml")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, report)
	}
	if !strings.Contains(report, `"findings": null`) && !strings.Contains(report, `"findings": []`) {
		t.Errorf("expected no findings at all:\n%s", report)
	}
}

func TestScanADirectoryWalksItRecursively(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile("../../testdata/clean.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), a, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../testdata/small.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.yml"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	// a non-YAML file in the tree should simply be ignored
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, report := out(t, "scan", "--format", "json", dir)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1: %s", code, report)
	}
	if !strings.Contains(report, `"fail": 7`) {
		t.Errorf("expected the findings from the nested small.yaml (a.yaml is clean):\n%s", report)
	}
}

func TestSarifOutputIsWellFormedAndOmitsWaivedFindings(t *testing.T) {
	code, report := out(t, "scan", "--format", "sarif", "--waivers", "../../testdata/waivers.yaml", "../../testdata/small.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(report, `"version": "2.1.0"`) {
		t.Error("not a SARIF 2.1.0 document")
	}
	if strings.Contains(report, "migration ticket") {
		t.Error("a waived finding's reason should not leak into SARIF")
	}
	if !strings.Contains(report, `"ruleId": "host-namespace"`) {
		t.Error("the expired-waiver finding should still be a real SARIF result")
	}
}

func TestUnreadablePathExitsTwo(t *testing.T) {
	code, _ := out(t, "scan", "does-not-exist.yaml")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestInvalidYAMLExitsTwoWithAReason(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("kind: [not: valid: yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _ := out(t, "scan", bad)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestEmptyDirectoryExitsTwo(t *testing.T) {
	code, _ := out(t, "scan", t.TempDir())
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (no .yaml/.yml files found)", code)
	}
}

func TestUnknownFailOnValueIsRejected(t *testing.T) {
	code, _ := out(t, "scan", "--fail-on", "severe", "../../testdata/clean.yaml")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestBadWaiverFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "waivers.yaml")
	if err := os.WriteFile(bad, []byte("waivers:\n  - rule: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _ := out(t, "scan", "--waivers", bad, "../../testdata/clean.yaml")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (missing kind/name/reason/expires)", code)
	}
}

func TestNoSubcommandPrintsUsage(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Fatalf("run(nil) = %d, want 2", code)
	}
	if code := run([]string{"bogus"}); code != 2 {
		t.Fatalf("run([bogus]) = %d, want 2", code)
	}
}
