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
		&cobra.Command{
			Use:   "create",
			Short: "Create baseline file",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), "baseline create scaffold ready")
				return nil
			},
		},
		&cobra.Command{
			Use:   "update",
			Short: "Update baseline file",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), "baseline update scaffold ready")
				return nil
			},
		},
	)

	return cmd
}
