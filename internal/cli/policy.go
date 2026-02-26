package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const defaultPolicyTemplate = `version: "1"
scan:
  default_mode: since-last-baseline
  exclude_paths:
    - "vendor/**"
    - "node_modules/**"
  max_file_size_kb: 500
allowlist:
  patterns:
    - regex: "AKIAIOSFODNN7EXAMPLE"
      reason: "AWS official example key"
severity:
  block_on: high
`

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage scan policies",
	}

	cmd.AddCommand(
		newPolicyInitCommand(),
		newPolicyCheckCommand(),
		newPolicyTestCommand(),
	)

	return cmd
}

func newPolicyInitCommand() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize policy file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if path == "" {
				path = ".secrethawk/policy.yaml"
			}

			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "policy already exists: %s\n", path)
				return nil
			}

			if err := os.WriteFile(path, []byte(defaultPolicyTemplate), 0o644); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "policy created: %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", ".secrethawk/policy.yaml", "Policy output path")
	return cmd
}

func newPolicyCheckCommand() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate policy syntax and semantics",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensurePolicy(path); err != nil {
				return &ExitError{Code: 2, Message: fmt.Sprintf("policy check failed: %v", err)}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "policy valid: %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", ".secrethawk/policy.yaml", "Policy path")
	return cmd
}

func newPolicyTestCommand() *cobra.Command {
	var customRulesPath string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run rule test cases",
		RunE: func(cmd *cobra.Command, args []string) error {
			rulesDir, err := resolveRulesDir("rules")
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			pass, fail, err := runPolicyTests(rulesDir, customRulesPath)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "policy tests: pass=%d fail=%d\n", pass, fail)
			if fail > 0 {
				return &ExitError{Code: 2, Message: "policy tests failed"}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&customRulesPath, "rules", "", "Custom rules path")
	return cmd
}
