package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newBaselineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage findings baseline",
	}

	cmd.AddCommand(
		newBaselineCreateCommand(),
		newBaselineUpdateCommand(),
	)

	return cmd
}

func newBaselineCreateCommand() *cobra.Command {
	var (
		path       string
		input      string
		target     string
		policyPath string
		rulesPath  string
		status     string
		reason     string
		addedBy    string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create baseline file",
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := collectFindingsFromInputOrScan(input, target, policyPath, rulesPath, path)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if err := writeBaseline(path, findings, status, reason, addedBy); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "baseline created: %s (entries=%d)\n", path, len(findings))
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", ".secrethawk/baseline.json", "Baseline file path")
	cmd.Flags().StringVar(&input, "input", "", "Findings JSON input path")
	cmd.Flags().StringVar(&target, "target", ".", "Scan target when --input is empty")
	cmd.Flags().StringVar(&policyPath, "policy", ".secrethawk/policy.yaml", "Policy path when scanning")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "Custom rules path when scanning")
	cmd.Flags().StringVar(&status, "status", "resolved", "Baseline status (resolved|skipped|false_positive)")
	cmd.Flags().StringVar(&reason, "reason", "added by baseline create", "Baseline reason")
	cmd.Flags().StringVar(&addedBy, "by", "unknown", "Actor email/name")
	return cmd
}

func newBaselineUpdateCommand() *cobra.Command {
	var (
		path       string
		input      string
		target     string
		policyPath string
		rulesPath  string
		status     string
		reason     string
		addedBy    string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update baseline file",
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := collectFindingsFromInputOrScan(input, target, policyPath, rulesPath, path)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if err := writeBaseline(path, findings, status, reason, addedBy); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "baseline updated: %s (entries=%d)\n", path, len(findings))
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", ".secrethawk/baseline.json", "Baseline file path")
	cmd.Flags().StringVar(&input, "input", "", "Findings JSON input path")
	cmd.Flags().StringVar(&target, "target", ".", "Scan target when --input is empty")
	cmd.Flags().StringVar(&policyPath, "policy", ".secrethawk/policy.yaml", "Policy path when scanning")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "Custom rules path when scanning")
	cmd.Flags().StringVar(&status, "status", "resolved", "Baseline status (resolved|skipped|false_positive)")
	cmd.Flags().StringVar(&reason, "reason", "updated by baseline update", "Baseline reason")
	cmd.Flags().StringVar(&addedBy, "by", "unknown", "Actor email/name")
	return cmd
}
