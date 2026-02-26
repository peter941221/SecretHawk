package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newReportCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "Generate incident report",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "report scaffold ready")
			return nil
		},
	}
}
