package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/peter941221/secrethawk/internal/output"
	"github.com/peter941221/secrethawk/internal/scan"
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

			runOpts := scan.Options{
				Target:             target,
				Staged:             opts.Staged,
				SinceRef:           opts.SinceRef,
				AllHistory:         opts.AllHistory,
				RulesPath:          opts.RulesPath,
				PolicyPath:         opts.PolicyPath,
				BaselinePath:       opts.BaselinePath,
				Severity:           strings.ToLower(opts.Severity),
				Validate:           opts.Validate,
				FailOn:             strings.ToLower(opts.FailOn),
				MaxTargetMegabytes: opts.MaxTargetMegabytes,
				Threads:            opts.Threads,
				Version:            BuildVersion,
				Now:                time.Now().UTC(),
			}

			result, err := scan.Run(context.Background(), runOpts)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			writer := cmd.OutOrStdout()
			if opts.OutputPath != "" {
				file, err := os.Create(opts.OutputPath)
				if err != nil {
					return &ExitError{Code: 2, Message: fmt.Sprintf("create output file: %v", err)}
				}
				defer file.Close()
				writer = file
			}

			if err := output.Write(result.Report, opts.Format, writer); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}

			if result.ShouldFail {
				return &ExitError{Code: 1, Message: "findings reached fail-on threshold"}
			}
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
