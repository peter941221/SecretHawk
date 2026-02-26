package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/peter941221/secrethawk/internal/patch"
	"github.com/spf13/cobra"
)

func newPatchCommand() *cobra.Command {
	var (
		replaceWith   string
		varPrefix     string
		commitChanges bool
		commitMessage string
		createPR      bool
		dryRun        bool
		target        string
		policyPath    string
		rulesPath     string
		baselinePath  string
	)

	cmd := &cobra.Command{
		Use:   "patch",
		Short: "Generate code replacement patch",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := patch.Apply(context.Background(), patch.Options{
				Target:       target,
				PolicyPath:   policyPath,
				RulesPath:    rulesPath,
				BaselinePath: baselinePath,
				ReplaceWith:  strings.ToLower(replaceWith),
				VarPrefix:    varPrefix,
				DryRun:       dryRun,
				Version:      BuildVersion,
			})
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			for _, c := range result.Changes {
				fmt.Fprintf(cmd.OutOrStdout(), "patched %s (%s -> %s) count=%d\n", c.File, c.RuleID, c.Replacement, c.Count)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "patch summary: %d replacements\n", len(result.Changes))

			if dryRun {
				return nil
			}

			if commitChanges {
				if commitMessage == "" {
					commitMessage = "chore(security): replace hardcoded secrets with secure references"
				}
				if err := runGit("add", "-A"); err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
				if err := runGit("commit", "-m", commitMessage); err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
				fmt.Fprintln(cmd.OutOrStdout(), "patch commit created")
			}

			if createPR {
				fmt.Fprintln(cmd.OutOrStdout(), "PR creation is not implemented yet; push branch and open PR manually")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&replaceWith, "replace-with", "env", "Replacement strategy: env|secretmanager|placeholder")
	cmd.Flags().StringVar(&varPrefix, "var-prefix", "", "Environment variable prefix")
	cmd.Flags().BoolVar(&commitChanges, "commit", false, "Create a git commit for patch")
	cmd.Flags().StringVar(&commitMessage, "commit-message", "", "Custom commit message")
	cmd.Flags().BoolVar(&createPR, "pr", false, "Create GitHub PR")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without writing files")
	cmd.Flags().StringVar(&target, "target", ".", "Scan target")
	cmd.Flags().StringVar(&policyPath, "policy", ".secrethawk/policy.yaml", "Policy file path")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "Custom rules path")
	cmd.Flags().StringVar(&baselinePath, "baseline", ".secrethawk/baseline.json", "Baseline file path")

	return cmd
}

func runGit(args ...string) error {
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s failed: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}
