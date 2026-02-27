package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/peter941221/secrethawk/internal/growth"
	"github.com/spf13/cobra"
)

func newGrowthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "growth",
		Short: "Growth automation workflow with human approval gate",
	}

	cmd.AddCommand(
		newGrowthInitCommand(),
		newGrowthPlanCommand(),
		newGrowthApproveCommand(),
		newGrowthExportCommand(),
	)
	return cmd
}

func newGrowthInitCommand() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create campaign brief template",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := growth.InitTemplate(path); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "growth brief template ready: %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", ".secrethawk/growth/campaign.yaml", "Growth campaign brief template output path")
	return cmd
}

func newGrowthPlanCommand() *cobra.Command {
	var (
		briefPath string
		output    string
	)
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Generate cross-channel draft queue from campaign brief",
		RunE: func(cmd *cobra.Command, args []string) error {
			brief, err := growth.LoadBrief(briefPath)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			queue, err := growth.GenerateQueue(brief, time.Now().UTC())
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if err := growth.SaveQueue(output, queue); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "growth queue generated: %s items=%d\n", output, len(queue.Items))
			return nil
		},
	}
	cmd.Flags().StringVar(&briefPath, "brief", ".secrethawk/growth/campaign.yaml", "Campaign brief YAML path")
	cmd.Flags().StringVar(&output, "output", ".secrethawk/growth/queue.json", "Generated growth queue JSON path")
	return cmd
}

func newGrowthApproveCommand() *cobra.Command {
	var (
		queuePath string
		id        string
		approver  string
	)
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve one queue item for publishing",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(id) == "" {
				return &ExitError{Code: 2, Message: "--id is required"}
			}
			if strings.TrimSpace(approver) == "" {
				approver = os.Getenv("USER")
				if strings.TrimSpace(approver) == "" {
					approver = os.Getenv("USERNAME")
				}
			}
			queue, err := growth.LoadQueue(queuePath)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if err := growth.Approve(&queue, id, approver, time.Now().UTC()); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if err := growth.SaveQueue(queuePath, queue); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "growth item approved: %s by %s\n", id, approver)
			return nil
		},
	}
	cmd.Flags().StringVar(&queuePath, "queue", ".secrethawk/growth/queue.json", "Growth queue JSON path")
	cmd.Flags().StringVar(&id, "id", "", "Queue item ID")
	cmd.Flags().StringVar(&approver, "approver", "", "Approver identity (name/email)")
	return cmd
}

func newGrowthExportCommand() *cobra.Command {
	var (
		queuePath string
		outDir    string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export approved queue items to publish cards (manual post)",
		RunE: func(cmd *cobra.Command, args []string) error {
			queue, err := growth.LoadQueue(queuePath)
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			files, err := growth.ExportApproved(&queue, outDir, time.Now().UTC())
			if err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			if err := growth.SaveQueue(queuePath, queue); err != nil {
				return &ExitError{Code: 2, Message: err.Error()}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "growth export completed: exported=%d out_dir=%s\n", len(files), outDir)
			for _, file := range files {
				fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", file)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&queuePath, "queue", ".secrethawk/growth/queue.json", "Growth queue JSON path")
	cmd.Flags().StringVar(&outDir, "out-dir", ".secrethawk/growth/out", "Output directory for publish cards")
	return cmd
}
