package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newPatchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patch",
		Short: "Generate code replacement patch",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "patch scaffold ready")
			return nil
		},
	}

	cmd.Flags().String("replace-with", "env", "Replacement strategy: env|secretmanager|placeholder")
	cmd.Flags().String("var-prefix", "", "Environment variable prefix")
	cmd.Flags().Bool("commit", false, "Create a git commit for patch")
	cmd.Flags().String("commit-message", "", "Custom commit message")
	cmd.Flags().Bool("pr", false, "Create GitHub PR")

	return cmd
}
