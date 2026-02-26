package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestScanFailOnReturnsExitError(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "config.py")
	if err := os.WriteFile(file, []byte(fmt.Sprintf("key=%q\n", testAWSKey())), 0o644); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"scan", tmp, "--fail-on", "high", "--policy", filepath.Join(tmp, "policy.yaml"), "--baseline", filepath.Join(tmp, "baseline.json")})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected exit error")
	}
	exitErr, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != 1 {
		t.Fatalf("expected exit code 1, got %d", exitErr.Code)
	}
}

func TestScanFailOnActiveDoesNotFailForUnknownOrErrorValidation(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "config.py")
	if err := os.WriteFile(file, []byte(fmt.Sprintf("key=%q\n", testAWSKey())), 0o644); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"scan", tmp, "--fail-on", "high", "--fail-on-active", "--policy", filepath.Join(tmp, "policy.yaml"), "--baseline", filepath.Join(tmp, "baseline.json")})
	err := root.Execute()
	if err != nil {
		t.Fatalf("expected no exit error, got %v output=%s", err, out.String())
	}
}

func testAWSKey() string {
	return "AKIA3EXA" + "MPLE7JKXQ4F7"
}
