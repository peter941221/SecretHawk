package cli

import "testing"

func TestRootCommandContainsTopLevelCommands(t *testing.T) {
	root := NewRootCommand()

	expected := []string{
		"scan",
		"validate",
		"remediate",
		"patch",
		"history-clean",
		"report",
		"policy",
		"connector",
		"baseline",
		"version",
	}

	for _, name := range expected {
		if findCommand(root, name) == nil {
			t.Fatalf("expected command %q to exist", name)
		}
	}
}

func TestPolicyCommandContainsSubcommands(t *testing.T) {
	root := NewRootCommand()
	policy := findCommand(root, "policy")
	if policy == nil {
		t.Fatal("policy command missing")
	}

	expected := []string{"init", "check", "test"}
	for _, name := range expected {
		if findCommand(policy, name) == nil {
			t.Fatalf("expected policy subcommand %q", name)
		}
	}
}

func findCommand(parent interface{ Commands() []*Command }, name string) *Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
