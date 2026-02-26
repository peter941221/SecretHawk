package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRemediateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Interactive remediation wizard",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "remediate scaffold ready")
			return nil
		},
	}

	cmd.Flags().Bool("interactive", true, "Enable interactive mode")
	cmd.Flags().String("input", "", "Read findings from scan JSON output")
	cmd.Flags().Bool("auto", false, "Auto-run all remediations (dangerous)")
	cmd.Flags().Bool("dry-run", false, "Show planned actions without executing")
	cmd.Flags().String("connector", "auto-detect", "Connector name override")

	return cmd
}
