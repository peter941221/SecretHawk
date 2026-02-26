package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newConnectorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connector",
		Short: "Manage external service connectors",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List available connectors",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), "connector list scaffold ready")
				return nil
			},
		},
		&cobra.Command{
			Use:   "test",
			Short: "Test connector configuration",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), "connector test scaffold ready")
				return nil
			},
		},
		&cobra.Command{
			Use:   "rotate",
			Short: "Rotate secret with connector",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), "connector rotate scaffold ready")
				return nil
			},
		},
	)

	return cmd
}
