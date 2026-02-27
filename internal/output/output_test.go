package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/peter941221/secrethawk/internal/model"
)

func TestWriteSARIF(t *testing.T) {
	report := model.FindingReport{
		Findings: []model.Finding{{
			RuleID:   "aws-access-key-id",
			RuleName: "AWS Access Key ID",
			Severity: "critical",
			Location: model.Location{File: "a.py", LineStart: 1, LineEnd: 1},
			Match:    model.Match{RawRedacted: "AKIA...ABCD"},
		}},
		Metadata: model.Metadata{Version: "test", ScannedAt: time.Now().UTC()},
	}

	var buf bytes.Buffer
	if err := Write(report, "sarif", &buf); err != nil {
		t.Fatal(err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["version"] != "2.1.0" {
		t.Fatalf("unexpected sarif version: %v", payload["version"])
	}
}

func TestWriteHumanIncludesSummaryCounts(t *testing.T) {
	report := model.FindingReport{
		Findings: []model.Finding{{
			RuleID:   "aws-access-key-id",
			RuleName: "AWS Access Key ID",
			Severity: "critical",
			Location: model.Location{File: "a.py", LineStart: 1, LineEnd: 1},
			Match:    model.Match{RawRedacted: "AKIA...ABCD"},
		}},
		Metadata: model.Metadata{
			Version:          "test",
			ScannedAt:        time.Now().UTC(),
			SeverityCounts:   map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 0},
			ValidationCounts: map[string]int{"active": 0, "inactive": 0, "unknown": 1, "error": 0},
		},
	}

	var buf bytes.Buffer
	if err := Write(report, "human", &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Severity: critical=1 high=0 medium=0 low=0") {
		t.Fatalf("missing severity summary: %s", out)
	}
	if !strings.Contains(out, "Validation: active=0 inactive=0 unknown=1 error=0") {
		t.Fatalf("missing validation summary: %s", out)
	}
}
