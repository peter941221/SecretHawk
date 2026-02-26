package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

type scanOptions struct {
	Staged             bool
	SinceRef           string
	AllHistory         bool
	RulesPath          string
	PolicyPath         string
	BaselinePath       string
	Format             string
	OutputPath         string
	Severity           string
	Validate           bool
	FailOn             string
	MaxTargetMegabytes int
	Threads            int
}

func newScanCommand() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Scan for secret leaks",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}

			// Placeholder: engine wiring comes in the next implementation milestone.
			fmt.Fprintf(cmd.OutOrStdout(), "scan scaffold ready (target=%s format=%s)\n", target, opts.Format)
			return nil
		},
	}

	cmd.Flags().BoolVar(&opts.Staged, "staged", false, "Scan only staged files")
	cmd.Flags().StringVar(&opts.SinceRef, "since", "", "Scan changes since commit/branch ref")
	cmd.Flags().BoolVar(&opts.AllHistory, "all-history", false, "Scan complete git history")
	cmd.Flags().StringVar(&opts.RulesPath, "rules", "", "Path to custom rules")
	cmd.Flags().StringVar(&opts.PolicyPath, "policy", ".secrethawk/policy.yaml", "Policy file path")
	cmd.Flags().StringVar(&opts.BaselinePath, "baseline", ".secrethawk/baseline.json", "Baseline file path")
	cmd.Flags().StringVar(&opts.Format, "format", "human", "Output format: human|json|sarif")
	cmd.Flags().StringVar(&opts.OutputPath, "output", "", "Output file path")
	cmd.Flags().StringVar(&opts.Severity, "severity", "low", "Minimum reported severity")
	cmd.Flags().BoolVar(&opts.Validate, "validate", false, "Validate whether secrets are active")
	cmd.Flags().StringVar(&opts.FailOn, "fail-on", "", "Exit non-zero when findings >= severity")
	cmd.Flags().IntVar(&opts.MaxTargetMegabytes, "max-target-megabytes", 50, "Skip files larger than this size in MB")
	cmd.Flags().IntVar(&opts.Threads, "threads", 0, "Parallel scanning workers (0=auto)")

	return cmd
}
