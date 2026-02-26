package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate whether findings are still active",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "validate scaffold ready")
			return nil
		},
	}
}
