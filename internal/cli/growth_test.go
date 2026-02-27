package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peter941221/secrethawk/internal/growth"
)

func TestGrowthInitPlanApproveExportFlow(t *testing.T) {
	tmp := t.TempDir()
	briefPath := filepath.Join(tmp, "campaign.yaml")
	queuePath := filepath.Join(tmp, "queue.json")
	outDir := filepath.Join(tmp, "out")

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"growth", "init", "--path", briefPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("growth init failed: %v", err)
	}
	if _, err := os.Stat(briefPath); err != nil {
		t.Fatalf("expected brief file: %v", err)
	}

	out.Reset()
	root = NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"growth", "plan", "--brief", briefPath, "--output", queuePath})
	if err := root.Execute(); err != nil {
		t.Fatalf("growth plan failed: %v output=%s", err, out.String())
	}
	queue, err := growth.LoadQueue(queuePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.Items) == 0 {
		t.Fatal("expected queue items")
	}

	itemID := queue.Items[0].ID
	out.Reset()
	root = NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"growth", "approve", "--queue", queuePath, "--id", itemID, "--approver", "peter"})
	if err := root.Execute(); err != nil {
		t.Fatalf("growth approve failed: %v output=%s", err, out.String())
	}

	out.Reset()
	root = NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"growth", "export", "--queue", queuePath, "--out-dir", outDir})
	if err := root.Execute(); err != nil {
		t.Fatalf("growth export failed: %v output=%s", err, out.String())
	}
	if !strings.Contains(out.String(), "exported=1") {
		t.Fatalf("expected one exported item, got output=%s", out.String())
	}
	files, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 export file, got %d", len(files))
	}
}
