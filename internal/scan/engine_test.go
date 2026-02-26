package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/peter941221/secrethawk/internal/baseline"
)

func TestRunDetectsAWSKey(t *testing.T) {
	tmp := t.TempDir()
	source := "aws_key = \"AKIA3EXAMPLE7JKXQ4F7\"\n"
	path := filepath.Join(tmp, "config.py")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		Target:             tmp,
		PolicyPath:         filepath.Join(tmp, "policy.yaml"),
		BaselinePath:       filepath.Join(tmp, "baseline.json"),
		Severity:           "low",
		MaxTargetMegabytes: 5,
		Version:            "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Report.Findings) == 0 {
		t.Fatal("expected finding")
	}
	if res.Report.Findings[0].RuleID != "aws-access-key-id" {
		t.Fatalf("unexpected rule id: %s", res.Report.Findings[0].RuleID)
	}
}

func TestRunRespectsAllowlistPattern(t *testing.T) {
	tmp := t.TempDir()
	source := "aws_key = \"AKIA3EXAMPLE7JKXQ4F7\"\n"
	path := filepath.Join(tmp, "config.py")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	policy := `version: "1"
allowlist:
  patterns:
    - regex: 'AKIA3EXAMPLE7JKXQ4F7'
      reason: test
severity:
  block_on: high
`
	policyPath := filepath.Join(tmp, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		Target:             tmp,
		PolicyPath:         policyPath,
		BaselinePath:       filepath.Join(tmp, "baseline.json"),
		Severity:           "critical",
		MaxTargetMegabytes: 5,
		Version:            "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Report.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(res.Report.Findings))
	}
}

func TestRunRespectsBaseline(t *testing.T) {
	tmp := t.TempDir()
	line := "aws_key = \"AKIA3EXAMPLE7JKXQ4F7\""
	path := filepath.Join(tmp, "config.py")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	basePath := filepath.Join(tmp, "baseline.json")
	base := baseline.File{
		Version: "1",
		Entries: []baseline.Entry{{
			RuleID:   "aws-access-key-id",
			File:     filepath.ToSlash(path),
			LineHash: baseline.ComputeLineHash(line),
			Status:   "resolved",
		}},
	}
	if err := baseline.Save(basePath, base); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		Target:             tmp,
		PolicyPath:         filepath.Join(tmp, "policy.yaml"),
		BaselinePath:       basePath,
		Severity:           "critical",
		MaxTargetMegabytes: 5,
		Version:            "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := len(res.Report.Findings); got != 0 {
		t.Fatalf("expected baseline suppression, got %d findings", got)
	}
}

func TestRunFailOnThreshold(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.py")
	if err := os.WriteFile(path, []byte("aws_key = \"AKIA3EXAMPLE7JKXQ4F7\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		Target:             tmp,
		PolicyPath:         filepath.Join(tmp, "policy.yaml"),
		BaselinePath:       filepath.Join(tmp, "baseline.json"),
		Severity:           "low",
		FailOn:             "high",
		MaxTargetMegabytes: 5,
		Version:            "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !res.ShouldFail {
		t.Fatal("expected fail-on threshold to trigger")
	}
}
