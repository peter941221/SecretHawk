package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newHistoryCleanCommand() *cobra.Command {
	var (
		findingID string
		cleanAll  bool
		method    string
		backup    bool
		secret    string
	)

	cmd := &cobra.Command{
		Use:   "history-clean",
		Short: "Clean leaked secrets from git history",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cleanAll && findingID == "" && secret == "" {
				return &ExitError{Code: 2, Message: "provide --all, --finding-id, or --secret"}
			}

			dirty, err := gitDirty()
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if dirty {
				return &ExitError{Code: 2, Message: "repository has uncommitted changes; commit or stash before history-clean"}
			}

			if backup {
				name := "backup/pre-secrethawk-clean-" + time.Now().UTC().Format("20060102-150405")
				if err := runGit("branch", name); err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "backup branch created: %s\n", name)
			}

			switch strings.ToLower(method) {
			case "bfg":
				fmt.Fprintln(cmd.OutOrStdout(), "bfg method selected. Run: bfg --replace-text <secrets.txt> .git")
			case "filter-repo":
				if secret == "" {
					return &ExitError{Code: 2, Message: "--secret is required for filter-repo method"}
				}
				replaceFile := ".secrethawk/tmp/filter-repo-replacements.txt"
				if err := os.MkdirAll(".secrethawk/tmp", 0o755); err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
				line := fmt.Sprintf("%s==>%s\n", secret, "<REDACTED_BY_SECRETHAWK>")
				if err := os.WriteFile(replaceFile, []byte(line), 0o600); err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
				if err := runCommand("git", "filter-repo", "--force", "--replace-text", replaceFile); err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
				fmt.Fprintln(cmd.OutOrStdout(), "git filter-repo finished")
			case "rebase":
				fmt.Fprintln(cmd.OutOrStdout(), "rebase method selected. Manually run interactive rebase and amend commits containing the secret.")
			default:
				return &ExitError{Code: 2, Message: "unsupported method: " + method}
			}

			fmt.Fprintln(cmd.OutOrStdout(), "warning: local history cleaned. force push and notify collaborators to rebase.")
			return nil
		},
	}

	cmd.Flags().StringVar(&findingID, "finding-id", "", "Specific finding ID to clean")
	cmd.Flags().BoolVar(&cleanAll, "all", false, "Clean all findings")
	cmd.Flags().StringVar(&method, "method", "bfg", "Method: bfg|filter-repo|rebase")
	cmd.Flags().BoolVar(&backup, "backup", true, "Create backup branch before cleanup")
	cmd.Flags().StringVar(&secret, "secret", "", "Raw secret to scrub (required for filter-repo)")

	return cmd
}

func gitDirty() (bool, error) {
	cmd := exec.Command("git", "status", "--porcelain")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("git status failed: %s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)) != "", nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}
