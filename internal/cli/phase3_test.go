package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peter941221/secrethawk/internal/model"
)

func TestConnectorListCommand(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"connector", "list"})
	if err := root.Execute(); err != nil {
		t.Fatalf("connector list failed: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "aws") || !strings.Contains(text, "github") || !strings.Contains(text, "slack") || !strings.Contains(text, "stripe") {
		t.Fatalf("unexpected connector list output: %s", text)
	}
}

func TestValidateRequiresInputOrSecret(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"validate"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPatchDryRunCommand(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "app.py")
	content := fmt.Sprintf("api_key = %q\n", "AKIA3EXA"+"MPLE7JKXQ4F7")
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"patch", "--target", tmp, "--policy", filepath.Join(tmp, "policy.yaml"), "--baseline", filepath.Join(tmp, "baseline.json"), "--dry-run"})
	if err := root.Execute(); err != nil {
		t.Fatalf("patch dry-run failed: %v output=%s", err, out.String())
	}

	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != content {
		t.Fatal("dry-run should not modify source file")
	}
}

func TestRemediateDryRunCommand(t *testing.T) {
	tmp := t.TempDir()
	findingsPath := filepath.Join(tmp, "findings.json")
	payload := model.FindingReport{
		Findings: []model.Finding{{
			ID:       "f-1",
			RuleID:   "aws-access-key-id",
			RuleName: "AWS Access Key ID",
			Severity: "critical",
			Location: model.Location{File: "src/a.py", LineStart: 1, LineEnd: 1},
			Match:    model.Match{RawRedacted: "AKIA...Q4F7", Length: 20},
		}},
		Metadata: model.Metadata{Version: "test", ScannedAt: time.Now().UTC()},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(findingsPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"remediate", "--input", findingsPath, "--auto", "--dry-run"})
	if err := root.Execute(); err != nil {
		t.Fatalf("remediate dry-run failed: %v", err)
	}
	if !strings.Contains(out.String(), "dry-run") {
		t.Fatalf("expected dry-run output, got: %s", out.String())
	}
}

func TestHistoryCleanRejectsDirtyRepo(t *testing.T) {
	tmp := t.TempDir()
	mustRun(t, tmp, "git", "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"history-clean", "--all"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected dirty-repo error")
	}
}

func mustRun(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v output=%s", name, args, err, string(out))
	}
}
