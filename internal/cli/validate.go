package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/peter941221/secrethawk/internal/connector"
	"github.com/spf13/cobra"
)

func newValidateCommand() *cobra.Command {
	var (
		input         string
		output        string
		connectorName string
		secret        string
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate whether findings are still active",
		RunE: func(cmd *cobra.Command, args []string) error {
			if secret != "" {
				if connectorName == "" {
					return &ExitError{Code: 2, Message: "--connector is required when --secret is used"}
				}
				c, err := connector.ByName(connectorName)
				if err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
				status, details := connector.ValidateWithConnector(context.Background(), c, secret)
				result := map[string]any{
					"connector": connectorName,
					"status":    status,
					"details":   details,
					"validated": time.Now().UTC().Format(time.RFC3339),
				}
				return writeValidationResult(cmd, output, result)
			}

			if input == "" {
				return &ExitError{Code: 2, Message: "provide either --secret or --input"}
			}
			report, err := loadFindingReport(input)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			for i := range report.Findings {
				rid := report.Findings[i].RuleID
				c := connector.FindByRuleID(rid)
				now := time.Now().UTC()
				report.Findings[i].Validation.ValidatedAt = &now
				if c == nil {
					report.Findings[i].Validation.Status = "unknown"
					report.Findings[i].Validation.Method = "no-connector"
					continue
				}
				if looksRedacted(report.Findings[i].Match.RawRedacted) {
					report.Findings[i].Validation.Status = "unknown"
					report.Findings[i].Validation.Method = "redacted-input"
					report.Findings[i].Validation.Details = map[string]any{"hint": "provide raw secret for direct validation"}
					continue
				}
				status, details := connector.ValidateWithConnector(context.Background(), c, report.Findings[i].Match.RawRedacted)
				report.Findings[i].Validation.Status = status
				report.Findings[i].Validation.Method = c.Name()
				report.Findings[i].Validation.Details = details
			}

			payload, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if output != "" {
				if err := os.WriteFile(output, payload, 0o644); err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "validation result written: %s\n", output)
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(payload))
			return nil
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "Findings JSON file from scan")
	cmd.Flags().StringVar(&output, "output", "", "Output file path")
	cmd.Flags().StringVar(&connectorName, "connector", "", "Connector name (aws|github)")
	cmd.Flags().StringVar(&secret, "secret", "", "Single secret value for direct validation")
	return cmd
}

func writeValidationResult(cmd *cobra.Command, output string, result map[string]any) error {
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return &ExitError{Code: 2, Message: err.Error()}
	}
	if output != "" {
		if err := os.WriteFile(output, payload, 0o644); err != nil {
			return &ExitError{Code: 2, Message: err.Error()}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "validation result written: %s\n", output)
		return nil
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(payload))
	return nil
}

func looksRedacted(v string) bool {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return true
	}
	return strings.Contains(trimmed, "...")
}
