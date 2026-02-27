package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peter941221/secrethawk/internal/cisync"
	"github.com/peter941221/secrethawk/internal/connector"
	"github.com/peter941221/secrethawk/internal/model"
	"github.com/peter941221/secrethawk/internal/patch"
	"github.com/peter941221/secrethawk/internal/scan"
	"github.com/spf13/cobra"
)

func newRemediateCommand() *cobra.Command {
	var (
		interactive    bool
		input          string
		autoRun        bool
		dryRun         bool
		connector      string
		target         string
		policyPath     string
		rulesPath      string
		baselinePath   string
		operator       string
		syncGHA        bool
		githubRepo     string
		githubTokenEnv string
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

			connectorSummary, err := runConnectorRemediation(context.Background(), findings, connector)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
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

			ghaSummary := githubSecretSyncSummary{}
			if syncGHA {
				ghaSummary, err = syncPatchedSecretsToGitHubActions(context.Background(), patchResult.Changes, githubRepo, githubTokenEnv, cmd.OutOrStdout())
				if err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
			}

			reportPath, err := writeRemediationReport(scanReport, operator)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "remediation complete: rotated=%d revoked=%d connector_errors=%d patched=%d gha_synced=%d gha_skipped=%d baseline=%s report=%s\n", connectorSummary.Rotated, connectorSummary.Revoked, connectorSummary.Errors, len(patchResult.Changes), ghaSummary.Updated, ghaSummary.Skipped, baselinePath, reportPath)
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
	cmd.Flags().BoolVar(&syncGHA, "sync-github-actions", false, "Sync patched env vars to GitHub Actions secrets")
	cmd.Flags().StringVar(&githubRepo, "github-repo", "", "GitHub repo in owner/repo format (default from GITHUB_REPOSITORY)")
	cmd.Flags().StringVar(&githubTokenEnv, "github-token-env", "GITHUB_TOKEN", "Env var name that stores GitHub token for secret sync")

	return cmd
}

type connectorRemediationSummary struct {
	Rotated int
	Revoked int
	Errors  int
}

func runConnectorRemediation(ctx context.Context, findings []model.Finding, forcedConnector string) (connectorRemediationSummary, error) {
	summary := connectorRemediationSummary{}
	var forced connector.Connector
	var err error
	if forcedConnector != "" {
		forced, err = connector.ByName(forcedConnector)
		if err != nil {
			return summary, err
		}
	}

	for _, f := range findings {
		c := forced
		if c == nil {
			c = connector.FindByRuleID(f.RuleID)
		}
		if c == nil {
			continue
		}
		if f.RawSecret == "" {
			continue
		}

		if _, err := c.Rotate(ctx, f.RawSecret); err == nil {
			summary.Rotated++
			continue
		}

		if action, revokeErr := c.Revoke(ctx, f.RawSecret); revokeErr == nil && action != nil && action.Success {
			summary.Revoked++
			continue
		}

		summary.Errors++
	}

	return summary, nil
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

type githubSecretSyncer interface {
	SyncRepoSecrets(ctx context.Context, repo string, values map[string]string) (cisync.SyncResult, error)
}

var newGitHubSecretSyncer = func(token string) githubSecretSyncer {
	return cisync.NewGitHubActionsClient(token, nil)
}

type githubSecretSyncSummary struct {
	Updated int
	Skipped int
}

func syncPatchedSecretsToGitHubActions(ctx context.Context, changes []patch.Change, repo string, tokenEnv string, out io.Writer) (githubSecretSyncSummary, error) {
	summary := githubSecretSyncSummary{}
	if strings.TrimSpace(tokenEnv) == "" {
		tokenEnv = "GITHUB_TOKEN"
	}
	token := strings.TrimSpace(os.Getenv(tokenEnv))
	if token == "" {
		return summary, fmt.Errorf("github secret sync enabled but token env %s is empty", tokenEnv)
	}
	if strings.TrimSpace(repo) == "" {
		repo = strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	}
	if strings.TrimSpace(repo) == "" {
		return summary, fmt.Errorf("github secret sync enabled but repo is empty; use --github-repo or GITHUB_REPOSITORY")
	}

	secretValues := map[string]string{}
	for _, ch := range changes {
		name := strings.TrimSpace(ch.VarName)
		if name == "" {
			summary.Skipped++
			continue
		}
		if _, exists := secretValues[name]; exists {
			continue
		}
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			summary.Skipped++
			continue
		}
		secretValues[name] = value
	}
	if len(secretValues) == 0 {
		fmt.Fprintln(out, "github-actions sync skipped: no env var values available for patched keys")
		return summary, nil
	}

	syncer := newGitHubSecretSyncer(token)
	res, err := syncer.SyncRepoSecrets(ctx, repo, secretValues)
	if err != nil {
		return summary, err
	}
	summary.Updated += res.Updated
	summary.Skipped += res.Skipped
	fmt.Fprintf(out, "github-actions sync: updated=%d skipped=%d attempted=%d\n", res.Updated, res.Skipped, res.Attempted)
	return summary, nil
}
