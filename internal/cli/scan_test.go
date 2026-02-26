package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

type Command = cobra.Command

func TestScanFlagDefaults(t *testing.T) {
	cmd := newScanCommand()

	tests := []struct {
		flag string
		want string
	}{
		{"format", "human"},
		{"policy", ".secrethawk/policy.yaml"},
		{"baseline", ".secrethawk/baseline.json"},
		{"severity", "low"},
		{"max-target-megabytes", "50"},
	}

	for _, tc := range tests {
		got := cmd.Flag(tc.flag)
		if got == nil {
			t.Fatalf("flag %q missing", tc.flag)
		}
		if got.DefValue != tc.want {
			t.Fatalf("flag %q default = %q, want %q", tc.flag, got.DefValue, tc.want)
		}
	}

	failOnActive := cmd.Flag("fail-on-active")
	if failOnActive == nil {
		t.Fatal("flag fail-on-active missing")
	}
	if failOnActive.DefValue != "false" {
		t.Fatalf("flag fail-on-active default = %q, want false", failOnActive.DefValue)
	}
}
