package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newHistoryCleanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history-clean",
		Short: "Clean leaked secrets from git history",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "history-clean scaffold ready")
			return nil
		},
	}

	cmd.Flags().String("finding-id", "", "Specific finding ID to clean")
	cmd.Flags().Bool("all", false, "Clean all findings")
	cmd.Flags().String("method", "bfg", "Method: bfg|filter-repo|rebase")
	cmd.Flags().Bool("backup", true, "Create backup branch before cleanup")

	return cmd
}
