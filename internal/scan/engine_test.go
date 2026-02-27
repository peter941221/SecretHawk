package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/peter941221/secrethawk/internal/baseline"
)

func TestRunDetectsAWSKey(t *testing.T) {
	tmp := t.TempDir()
	source := fmt.Sprintf("aws_key = %q\n", testAWSKey())
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
	if res.Report.Metadata.SeverityCounts["critical"] < 1 {
		t.Fatalf("expected critical severity count, got %+v", res.Report.Metadata.SeverityCounts)
	}
	if res.Report.Metadata.ValidationCounts["unknown"] < 1 {
		t.Fatalf("expected unknown validation count, got %+v", res.Report.Metadata.ValidationCounts)
	}
}

func TestRunRespectsAllowlistPattern(t *testing.T) {
	tmp := t.TempDir()
	source := fmt.Sprintf("aws_key = %q\n", testAWSKey())
	path := filepath.Join(tmp, "config.py")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	policy := fmt.Sprintf(`version: "1"
allowlist:
  patterns:
    - regex: '%s'
      reason: test
severity:
  block_on: high
`, testAWSKey())
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
	line := fmt.Sprintf("aws_key = %q", testAWSKey())
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
	if err := os.WriteFile(path, []byte(fmt.Sprintf("aws_key = %q\n", testAWSKey())), 0o644); err != nil {
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

func TestRunFailOnActiveOnlyIgnoresNonActiveValidation(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.py")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("aws_key = %q\n", testAWSKey())), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		Target:             tmp,
		PolicyPath:         filepath.Join(tmp, "policy.yaml"),
		BaselinePath:       filepath.Join(tmp, "baseline.json"),
		Severity:           "low",
		Validate:           true,
		FailOn:             "high",
		FailOnActive:       true,
		MaxTargetMegabytes: 5,
		Version:            "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.ShouldFail {
		t.Fatal("expected fail-on-active to ignore non-active validation statuses")
	}
}

func testAWSKey() string {
	return "AKIA3EXA" + "MPLE7JKXQ4F7"
}

func TestRunGenericEntropyHasMediumConfidence(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "token.txt")
	if err := os.WriteFile(path, []byte("x = \"abcdefghijklmnopqrstuvwxyz1234567890ABCD\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		Target:             tmp,
		PolicyPath:         filepath.Join(tmp, "policy.yaml"),
		BaselinePath:       filepath.Join(tmp, "baseline.json"),
		Severity:           "medium",
		MaxTargetMegabytes: 5,
		Version:            "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range res.Report.Findings {
		if f.RuleID == "generic-high-entropy" {
			found = true
			if f.Confidence != "medium" {
				t.Fatalf("expected medium confidence, got %s", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("expected generic-high-entropy finding")
	}
}
