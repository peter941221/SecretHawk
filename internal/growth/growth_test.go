package growth

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateQueueBuildsDraftItems(t *testing.T) {
	brief := Brief{
		Name:         "wave1",
		Product:      "SecretHawk",
		OneLiner:     "Secret pipeline",
		CTAURL:       "https://example.com",
		Audience:     "devops",
		KeyPoints:    []string{"point-a", "point-b"},
		Channels:     []string{"x", "linkedin"},
		PublishStart: "2026-03-03T09:00:00",
		Timezone:     "UTC",
	}
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	queue, err := GenerateQueue(brief, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.Items) != 4 {
		t.Fatalf("expected 4 items, got %d", len(queue.Items))
	}
	for _, item := range queue.Items {
		if item.Status != StatusDraft {
			t.Fatalf("expected draft status, got %s", item.Status)
		}
		if !strings.Contains(item.UTMURL, "utm_source=") {
			t.Fatalf("expected utm url, got %s", item.UTMURL)
		}
	}
}

func TestApproveAndExportApproved(t *testing.T) {
	brief := Brief{
		Name:         "wave2",
		Product:      "SecretHawk",
		OneLiner:     "Secret pipeline",
		CTAURL:       "https://example.com",
		Audience:     "founder",
		KeyPoints:    []string{"point-a"},
		Channels:     []string{"x"},
		PublishStart: "2026-03-03T09:00:00",
		Timezone:     "UTC",
	}
	queue, err := GenerateQueue(brief, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(queue.Items))
	}
	id := queue.Items[0].ID

	if err := Approve(&queue, id, "peter", time.Date(2026, 3, 1, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if queue.Items[0].Status != StatusApproved {
		t.Fatalf("expected approved status, got %s", queue.Items[0].Status)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	files, err := ExportApproved(&queue, outDir, time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 exported file, got %d", len(files))
	}
	if queue.Items[0].Status != StatusExported {
		t.Fatalf("expected exported status, got %s", queue.Items[0].Status)
	}
}
