package patch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyPatchesOnlyCodeFiles(t *testing.T) {
	tmp := t.TempDir()
	pyPath := filepath.Join(tmp, "app.py")
	mdPath := filepath.Join(tmp, "README.md")
	secret := "AKIA3EXAMPLE7JKXQ4F7"

	if err := os.WriteFile(pyPath, []byte("k = \""+secret+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mdPath, []byte("demo key: "+secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Apply(context.Background(), Options{
		Target:       tmp,
		PolicyPath:   filepath.Join(tmp, "policy.yaml"),
		BaselinePath: filepath.Join(tmp, "baseline.json"),
		ReplaceWith:  "env",
		Version:      "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) == 0 {
		t.Fatal("expected at least one patch change")
	}
	for _, c := range res.Changes {
		if strings.HasSuffix(strings.ToLower(c.File), ".md") {
			t.Fatalf("markdown file should not be patched: %s", c.File)
		}
	}

	pyOut, err := os.ReadFile(pyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pyOut), secret) {
		t.Fatal("python source should be patched")
	}

	mdOut, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mdOut), secret) {
		t.Fatal("markdown content should remain unchanged")
	}
}
