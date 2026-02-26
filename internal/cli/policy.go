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
				return err
			}

			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "policy already exists: %s\n", path)
				return nil
			}

			if err := os.WriteFile(path, []byte(defaultPolicyTemplate), 0o644); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "policy created: %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", ".secrethawk/policy.yaml", "Policy output path")
	return cmd
}

func newPolicyCheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Validate policy syntax and semantics",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "policy check scaffold ready")
			return nil
		},
	}
}

func newPolicyTestCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run rule test cases",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "policy test scaffold ready")
			return nil
		},
	}
}
