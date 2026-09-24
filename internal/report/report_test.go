package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sriharifortitude/kubeshield/internal/rules"
	"github.com/sriharifortitude/kubeshield/internal/waiver"
)

func sample() Result {
	rows := []Row{
		{Finding: rules.Finding{
			RuleID: "privileged-container", Severity: rules.Critical, File: "deploy.yaml",
			Kind: "Pod", Namespace: "prod", Name: "web", Container: "app",
			Message: "securityContext.privileged is true", Remediation: "set it to false",
		}},
		{Finding: rules.Finding{
			RuleID: "run-as-root", Severity: rules.Medium, File: "deploy.yaml",
			Kind: "Pod", Namespace: "prod", Name: "legacy-worker",
			Message: "runAsNonRoot is not set to true", Remediation: "set securityContext.runAsNonRoot: true",
		}, WaiverOutcome: waiver.Waived, Waiver: &waiver.Entry{Reason: "migration ticket JIRA-1", Expires: "2030-01-01"}},
		{Finding: rules.Finding{
			RuleID: "host-namespace", Severity: rules.Critical, File: "deploy.yaml",
			Kind: "Pod", Namespace: "prod", Name: "debug-tool",
			Message: "spec.hostNetwork is true", Remediation: "remove hostNetwork",
		}, WaiverOutcome: waiver.Expired, Waiver: &waiver.Entry{Reason: "temporary", Expires: "2025-01-01"}},
	}
	return NewResult(rows)
}

func TestCountsBucketsEachRowExactlyOnce(t *testing.T) {
	c := sample().Counts()
	if c.Fail != 1 || c.Waived != 1 || c.ExpiredWaiver != 1 {
		t.Fatalf("got %+v, want Fail=1 Waived=1 ExpiredWaiver=1", c)
	}
}

func TestFailingExcludesWaivedButIncludesExpired(t *testing.T) {
	failing := sample().Failing(rules.Low)
	if len(failing) != 2 {
		t.Fatalf("got %d, want 2 (the real fail and the expired waiver)", len(failing))
	}
	for _, row := range failing {
		if row.WaiverOutcome == waiver.Waived {
			t.Errorf("an actively waived row should never be in Failing(): %+v", row)
		}
	}
}

func TestFailingRespectsTheSeverityThreshold(t *testing.T) {
	// run-as-root is Medium and waived (excluded anyway); the two
	// Critical findings should both survive a Critical threshold.
	failing := sample().Failing(rules.Critical)
	if len(failing) != 2 {
		t.Fatalf("got %d, want 2", len(failing))
	}
}

func TestTerminalNamesTheResourceAndContainer(t *testing.T) {
	out := Terminal(sample())
	if !strings.Contains(out, "prod/Pod/web (app)") {
		t.Errorf("missing resource+container location:\n%s", out)
	}
	if !strings.Contains(out, "prod/Pod/legacy-worker") {
		t.Errorf("missing resource location:\n%s", out)
	}
	if !strings.Contains(out, "WAIVER EXPIRED") {
		t.Errorf("missing EXPIRED label:\n%s", out)
	}
	if !strings.Contains(out, "3 findings: 1 failing, 1 waived, 1 expired waivers") {
		t.Errorf("missing or wrong summary line:\n%s", out)
	}
}

func TestJSONIncludesEveryFieldAndTheSummary(t *testing.T) {
	data, err := JSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Summary  Counts    `json:"summary"`
		Findings []jsonRow `json:"findings"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Summary.Fail != 1 {
		t.Errorf("summary = %+v", parsed.Summary)
	}
	if len(parsed.Findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(parsed.Findings))
	}
	var sawContainer bool
	for _, f := range parsed.Findings {
		if f.Container == "app" {
			sawContainer = true
		}
	}
	if !sawContainer {
		t.Error("expected the container-scoped finding to carry its container name")
	}
}

func TestSARIFOmitsWaivedButKeepsExpired(t *testing.T) {
	data, err := SARIF(sample())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Runs[0].Tool.Driver.Rules) != len(rules.All()) {
		t.Fatalf("declared %d rules, want all %d", len(parsed.Runs[0].Tool.Driver.Rules), len(rules.All()))
	}
	if len(parsed.Runs[0].Results) != 2 {
		t.Fatalf("got %d results, want 2 (waived omitted, expired kept)", len(parsed.Runs[0].Results))
	}
}
