package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peter941221/secrethawk/internal/baseline"
	"github.com/peter941221/secrethawk/internal/config"
	"github.com/peter941221/secrethawk/internal/model"
	"github.com/peter941221/secrethawk/internal/rules"
	"github.com/peter941221/secrethawk/internal/scan"
)

func loadFindingReport(path string) (model.FindingReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.FindingReport{}, err
	}
	var report model.FindingReport
	if err := json.Unmarshal(data, &report); err != nil {
		return model.FindingReport{}, fmt.Errorf("parse findings json: %w", err)
	}
	return report, nil
}

func resolveRulesDir(defaultDir string) (string, error) {
	if defaultDir == "" {
		defaultDir = "rules"
	}
	if info, err := os.Stat(defaultDir); err == nil && info.IsDir() && hasYAML(defaultDir) {
		return defaultDir, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	cur := cwd
	for {
		candidate := filepath.Join(cur, defaultDir)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() && hasYAML(candidate) {
			return candidate, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return "", fmt.Errorf("rules directory not found: %s", defaultDir)
}

func hasYAML(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			return true
		}
	}
	return false
}

func collectFindingsFromInputOrScan(input string, target string, policyPath string, rulesPath string, baselinePath string) ([]model.Finding, error) {
	if input != "" {
		report, err := loadFindingReport(input)
		if err != nil {
			return nil, err
		}
		return report.Findings, nil
	}

	res, err := scan.Run(context.Background(), scan.Options{
		Target:             target,
		PolicyPath:         policyPath,
		RulesPath:          rulesPath,
		BaselinePath:       baselinePath,
		Severity:           "low",
		MaxTargetMegabytes: 50,
		Version:            BuildVersion,
		Now:                time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	return res.Report.Findings, nil
}

func runPolicyTests(defaultRulesDir string, customRulesPath string) (int, int, error) {
	loaded, err := rules.Load(defaultRulesDir, customRulesPath)
	if err != nil {
		return 0, 0, err
	}

	pass := 0
	fail := 0
	for _, r := range loaded {
		if len(r.Tests.Positive) < 2 || len(r.Tests.Negative) < 2 {
			fail++
			continue
		}

		for _, tc := range r.Tests.Positive {
			got := rules.TestRuleAgainstInput(r, tc.Input)
			if got == tc.ShouldMatch {
				pass++
			} else {
				fail++
			}
		}
		for _, tc := range r.Tests.Negative {
			got := rules.TestRuleAgainstInput(r, tc.Input)
			if got == tc.ShouldMatch {
				pass++
			} else {
				fail++
			}
		}
	}
	return pass, fail, nil
}

func writeBaseline(path string, findings []model.Finding, status string, reason string, addedBy string) error {
	for i := range findings {
		if findings[i].LineHash == "" {
			findings[i].LineHash = baseline.ComputeLineHash(findings[i].ID)
		}
	}

	current, err := baseline.Load(path)
	if err != nil {
		return err
	}
	updated := baseline.UpsertEntries(current, findings, status, reason, addedBy)
	return baseline.Save(path, updated)
}

func ensurePolicy(path string) error {
	return config.ValidatePolicy(path)
}
