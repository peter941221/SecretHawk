package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/peter941221/secrethawk/internal/model"
)

func Write(report model.FindingReport, format string, w io.Writer) error {
	switch strings.ToLower(format) {
	case "human":
		writeHuman(report, w)
		return nil
	case "json":
		return writeJSON(report, w)
	case "sarif":
		return writeSARIF(report, w)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func writeHuman(report model.FindingReport, w io.Writer) {
	fmt.Fprintln(w, "SecretHawk scan result")
	fmt.Fprintln(w, "--------------------")
	for _, f := range report.Findings {
		fmt.Fprintf(w, "%s %s\n", severityBadge(f.Severity), strings.ToUpper(f.RuleName))
		fmt.Fprintf(w, "  File:   %s:%d\n", f.Location.File, f.Location.LineStart)
		fmt.Fprintf(w, "  Match:  %s\n", f.Match.RawRedacted)
		fmt.Fprintf(w, "  Confidence: %s\n", strings.ToUpper(f.Confidence))
		fmt.Fprintf(w, "  Status: %s\n", strings.ToUpper(defaultValidationStatus(f.Validation.Status)))
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Summary: %d findings\n", len(report.Findings))
	if len(report.Metadata.SeverityCounts) > 0 {
		fmt.Fprintf(w, "  Severity: critical=%d high=%d medium=%d low=%d\n",
			report.Metadata.SeverityCounts["critical"],
			report.Metadata.SeverityCounts["high"],
			report.Metadata.SeverityCounts["medium"],
			report.Metadata.SeverityCounts["low"],
		)
	}
	if len(report.Metadata.ValidationCounts) > 0 {
		fmt.Fprintf(w, "  Validation: active=%d inactive=%d unknown=%d error=%d\n",
			report.Metadata.ValidationCounts["active"],
			report.Metadata.ValidationCounts["inactive"],
			report.Metadata.ValidationCounts["unknown"],
			report.Metadata.ValidationCounts["error"],
		)
	}
}

func writeJSON(report model.FindingReport, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func writeSARIF(report model.FindingReport, w io.Writer) error {
	type artifactLocation struct {
		URI string `json:"uri"`
	}
	type region struct {
		StartLine   int `json:"startLine"`
		EndLine     int `json:"endLine"`
		StartColumn int `json:"startColumn,omitempty"`
		EndColumn   int `json:"endColumn,omitempty"`
	}
	type physicalLocation struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
		Region           region           `json:"region"`
	}
	type location struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   any        `json:"message"`
		Locations []location `json:"locations"`
	}

	results := make([]result, 0, len(report.Findings))
	for _, f := range report.Findings {
		results = append(results, result{
			RuleID: f.RuleID,
			Level:  sarifLevel(f.Severity),
			Message: map[string]string{
				"text": fmt.Sprintf("%s detected: %s", f.RuleName, f.Match.RawRedacted),
			},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: f.Location.File},
					Region: region{
						StartLine:   f.Location.LineStart,
						EndLine:     f.Location.LineEnd,
						StartColumn: f.Location.ColumnStart,
						EndColumn:   f.Location.ColumnEnd,
					},
				},
			}},
		})
	}

	sarif := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":            "secrethawk",
						"semanticVersion": report.Metadata.Version,
					},
				},
				"results": results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}

func severityBadge(level string) string {
	switch level {
	case "critical":
		return "[CRITICAL]"
	case "high":
		return "[HIGH]"
	case "medium":
		return "[MEDIUM]"
	default:
		return "[LOW]"
	}
}

func sarifLevel(level string) string {
	switch level {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func defaultValidationStatus(status string) string {
	if strings.TrimSpace(status) == "" {
		return "unknown"
	}
	return status
}
