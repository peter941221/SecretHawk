package cli

import (
	"context"
	"fmt"

	"github.com/peter941221/secrethawk/internal/connector"
	"github.com/spf13/cobra"
)

func newConnectorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connector",
		Short: "Manage external service connectors",
	}

	cmd.AddCommand(
		newConnectorListCommand(),
		newConnectorTestCommand(),
		newConnectorRotateCommand(),
	)

	return cmd
}

func newConnectorListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available connectors",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, c := range connector.Registry() {
				fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n", c.Name(), c.DisplayName())
			}
			return nil
		},
	}
}

func newConnectorTestCommand() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test connector configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return &ExitError{Code: 2, Message: "--name is required"}
			}
			c, err := connector.ByName(name)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			pf, err := c.PreflightCheck(context.Background())
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if pf.Ready {
				fmt.Fprintf(cmd.OutOrStdout(), "connector %s ready\n", name)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "connector %s missing prerequisites:\n", name)
			for _, m := range pf.Missing {
				fmt.Fprintf(cmd.OutOrStdout(), "- %s: %s (%s)\n", m.Name, m.Description, m.HowToFix)
			}
			return &ExitError{Code: 2, Message: "connector preflight failed"}
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Connector name")
	return cmd
}

func newConnectorRotateCommand() *cobra.Command {
	var (
		name   string
		secret string
	)

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate secret with connector",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" || secret == "" {
				return &ExitError{Code: 2, Message: "--name and --secret are required"}
			}
			c, err := connector.ByName(name)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			result, err := c.Rotate(context.Background(), secret)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rotate result: revoked=%v new_key=%s stored_at=%s\n", result.OldKeyRevoked, result.NewKeyID, result.StoredAt)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Connector name")
	cmd.Flags().StringVar(&secret, "secret", "", "Secret value")
	return cmd
}
