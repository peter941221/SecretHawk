package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/peter941221/secrethawk/internal/model"
	"github.com/peter941221/secrethawk/internal/patch"
	"github.com/peter941221/secrethawk/internal/scan"
	"github.com/spf13/cobra"
)

func newRemediateCommand() *cobra.Command {
	var (
		interactive  bool
		input        string
		autoRun      bool
		dryRun       bool
		connector    string
		target       string
		policyPath   string
		rulesPath    string
		baselinePath string
		operator     string
	)

	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Interactive remediation wizard",
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, scanReport, err := remediateInput(input, target, policyPath, rulesPath, baselinePath)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if len(findings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no findings to remediate")
				return nil
			}

			if interactive && !autoRun {
				fmt.Fprintf(cmd.OutOrStdout(), "remediation plan (%d findings):\n", len(findings))
				fmt.Fprintln(cmd.OutOrStdout(), "1) rotate/revoke keys via connector (manual where needed)")
				fmt.Fprintln(cmd.OutOrStdout(), "2) patch code references to env vars")
				fmt.Fprintln(cmd.OutOrStdout(), "3) update baseline and generate incident report")
				fmt.Fprintln(cmd.OutOrStdout(), "run with --auto to execute")
				return nil
			}

			if connector != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "connector selected: %s\n", connector)
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would patch %d findings, update baseline, and generate report\n", len(findings))
				return nil
			}

			patchResult, err := patch.Apply(context.Background(), patch.Options{
				Target:       target,
				PolicyPath:   policyPath,
				RulesPath:    rulesPath,
				BaselinePath: baselinePath,
				ReplaceWith:  "env",
				VarPrefix:    "",
				DryRun:       false,
				Version:      BuildVersion,
			})
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			if err := writeBaseline(baselinePath, findings, "resolved", "remediated", operator); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			reportPath, err := writeRemediationReport(scanReport, operator)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "remediation complete: patched=%d baseline=%s report=%s\n", len(patchResult.Changes), baselinePath, reportPath)
			return nil
		},
	}

	cmd.Flags().BoolVar(&interactive, "interactive", true, "Enable interactive mode")
	cmd.Flags().StringVar(&input, "input", "", "Read findings from scan JSON output")
	cmd.Flags().BoolVar(&autoRun, "auto", false, "Auto-run all remediations")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show planned actions without executing")
	cmd.Flags().StringVar(&connector, "connector", "", "Connector name override")
	cmd.Flags().StringVar(&target, "target", ".", "Scan target")
	cmd.Flags().StringVar(&policyPath, "policy", ".secrethawk/policy.yaml", "Policy file")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "Custom rules path")
	cmd.Flags().StringVar(&baselinePath, "baseline", ".secrethawk/baseline.json", "Baseline file path")
	cmd.Flags().StringVar(&operator, "operator", "unknown", "Operator name/email")

	return cmd
}

func remediateInput(input string, target string, policyPath string, rulesPath string, baselinePath string) ([]model.Finding, model.FindingReport, error) {
	if input != "" {
		report, err := loadFindingReport(input)
		if err != nil {
			return nil, model.FindingReport{}, err
		}
		return report.Findings, report, nil
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
		return nil, model.FindingReport{}, err
	}
	return res.Report.Findings, res.Report, nil
}

func writeRemediationReport(scanReport model.FindingReport, operator string) (string, error) {
	now := time.Now().UTC().Format("2006-01-02-150405")
	path := filepath.Join(".secrethawk", "reports", now+".md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	body := renderIncidentReport(scanReport, operator)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
