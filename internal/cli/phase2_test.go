package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/peter941221/secrethawk/internal/model"
)

func TestPolicyCheckCommand(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	policy := `version: "1"
severity:
  block_on: high
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"policy", "check", "--path", policyPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("policy check failed: %v\noutput: %s", err, out.String())
	}
}

func TestPolicyTestCommand(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"policy", "test"})
	if err := root.Execute(); err != nil {
		t.Fatalf("policy test failed: %v\noutput: %s", err, out.String())
	}
}

func TestBaselineCreateAndReportCommand(t *testing.T) {
	tmp := t.TempDir()
	findingsPath := filepath.Join(tmp, "findings.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	reportPath := filepath.Join(tmp, "incident.md")

	report := model.FindingReport{
		Schema: "https://secrethawk.dev/schemas/finding-v1.json",
		Findings: []model.Finding{{
			ID:       "f-1",
			RuleID:   "aws-access-key-id",
			RuleName: "AWS Access Key ID",
			Severity: "critical",
			Category: "cloud-credential",
			Location: model.Location{File: "src/config.py", LineStart: 10, LineEnd: 10},
			Match:    model.Match{RawRedacted: "AKIA...Q4F7", Length: 20},
			Validation: model.Validation{
				Status: "unknown",
			},
			Remediation: model.Remediation{Status: "pending"},
		}},
		Metadata: model.Metadata{
			Tool:      "secrethawk",
			Version:   "test",
			ScannedAt: time.Now().UTC(),
		},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(findingsPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var out1 bytes.Buffer
	root.SetOut(&out1)
	root.SetErr(&out1)
	root.SetArgs([]string{"baseline", "create", "--input", findingsPath, "--path", baselinePath, "--by", "tester"})
	if err := root.Execute(); err != nil {
		t.Fatalf("baseline create failed: %v\noutput: %s", err, out1.String())
	}
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("baseline file missing: %v", err)
	}

	root2 := NewRootCommand()
	var out2 bytes.Buffer
	root2.SetOut(&out2)
	root2.SetErr(&out2)
	root2.SetArgs([]string{"report", "--input", findingsPath, "--output", reportPath, "--operator", "tester"})
	if err := root2.Execute(); err != nil {
		t.Fatalf("report command failed: %v\noutput: %s", err, out2.String())
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("report file missing: %v", err)
	}
}
