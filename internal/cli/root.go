package cli

import "github.com/spf13/cobra"

// BuildVersion is overridden by release tooling (e.g. goreleaser).
var BuildVersion = "0.1.0-dev"

// GlobalOptions are shared flags for future command implementations.
type GlobalOptions struct {
	Verbose bool
}

func NewRootCommand() *cobra.Command {
	opts := &GlobalOptions{}

	cmd := &cobra.Command{
		Use:           "secrethawk",
		Short:         "Secret remediation CLI",
		Long:          "SecretHawk helps detect, validate, and remediate leaked secrets.",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.PersistentFlags().BoolVar(&opts.Verbose, "verbose", false, "Enable verbose logging")

	cmd.AddCommand(
		newScanCommand(),
		newValidateCommand(),
		newRemediateCommand(),
		newPatchCommand(),
		newHistoryCleanCommand(),
		newReportCommand(),
		newPolicyCommand(),
		newConnectorCommand(),
		newBaselineCommand(),
		newVersionCommand(),
	)

	return cmd
}
