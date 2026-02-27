package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peter941221/secrethawk/internal/cisync"
	"github.com/peter941221/secrethawk/internal/model"
	"github.com/peter941221/secrethawk/internal/patch"
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

func TestValidateInputSkipsRedactedSecrets(t *testing.T) {
	tmp := t.TempDir()
	inputPath := filepath.Join(tmp, "findings.json")
	payload := model.FindingReport{
		Findings: []model.Finding{{
			ID:       "f-1",
			RuleID:   "github-pat-classic",
			RuleName: "GitHub PAT Classic",
			Severity: "high",
			Location: model.Location{File: "x.txt", LineStart: 1, LineEnd: 1},
			Match:    model.Match{RawRedacted: "ghp_1234...abcd", Length: 40},
		}},
		Metadata: model.Metadata{Version: "test", ScannedAt: time.Now().UTC()},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"validate", "--input", inputPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate input failed: %v", err)
	}

	var got model.FindingReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("parse validate output failed: %v output=%s", err, out.String())
	}
	if len(got.Findings) != 1 {
		t.Fatalf("unexpected findings count: %d", len(got.Findings))
	}
	if got.Findings[0].Validation.Method != "redacted-input" || got.Findings[0].Validation.Status != "unknown" {
		t.Fatalf("unexpected validation result: %+v", got.Findings[0].Validation)
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

func TestRunConnectorRemediationUnknownConnector(t *testing.T) {
	_, err := runConnectorRemediation(context.Background(), []model.Finding{}, "unknown-connector")
	if err == nil {
		t.Fatal("expected connector lookup error")
	}
}

func TestRunConnectorRemediationForcedGithub(t *testing.T) {
	findings := []model.Finding{{
		RuleID:    "github-pat-classic",
		RawSecret: "ghp_1234567890abcdefghij1234567890abcdef",
	}}
	summary, err := runConnectorRemediation(context.Background(), findings, "github")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Rotated != 1 {
		t.Fatalf("expected 1 rotated, got %+v", summary)
	}
}

func TestSyncPatchedSecretsToGitHubActionsMissingToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	_, err := syncPatchedSecretsToGitHubActions(context.Background(), []patch.Change{{VarName: "AWS_ACCESS_KEY_ID"}}, "owner/repo", "GITHUB_TOKEN", &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected token error")
	}
}

func TestSyncPatchedSecretsToGitHubActionsSuccess(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "token-x")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA1111222233334444")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-value")

	oldFactory := newGitHubSecretSyncer
	defer func() { newGitHubSecretSyncer = oldFactory }()

	fake := &fakeSecretSyncer{}
	newGitHubSecretSyncer = func(token string) githubSecretSyncer {
		if token != "token-x" {
			t.Fatalf("unexpected token: %s", token)
		}
		return fake
	}

	buf := &bytes.Buffer{}
	summary, err := syncPatchedSecretsToGitHubActions(context.Background(), []patch.Change{
		{VarName: "AWS_ACCESS_KEY_ID"},
		{VarName: "AWS_SECRET_ACCESS_KEY"},
		{VarName: "MISSING_SECRET"},
	}, "", "GITHUB_TOKEN", buf)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Updated != 2 {
		t.Fatalf("expected updated=2 got %+v", summary)
	}
	if summary.Skipped < 1 {
		t.Fatalf("expected skipped>=1 got %+v", summary)
	}
	if fake.repo != "owner/repo" {
		t.Fatalf("unexpected repo: %s", fake.repo)
	}
	if len(fake.values) != 2 {
		t.Fatalf("unexpected values: %+v", fake.values)
	}
}

type fakeSecretSyncer struct {
	repo   string
	values map[string]string
}

func (f *fakeSecretSyncer) SyncRepoSecrets(ctx context.Context, repo string, values map[string]string) (cisync.SyncResult, error) {
	_ = ctx
	f.repo = repo
	f.values = values
	return cisync.SyncResult{Attempted: len(values), Updated: len(values), Skipped: 0}, nil
}

func mustRun(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v output=%s", name, args, err, string(out))
	}
}
