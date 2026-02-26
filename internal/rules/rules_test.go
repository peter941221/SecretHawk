package rules

import "testing"

func TestAllRulesMatchBundledCases(t *testing.T) {
	rs, err := Load("../../rules", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rs {
		for _, tc := range rule.Tests.Positive {
			if !TestRuleAgainstInput(rule, tc.Input) {
				t.Fatalf("rule=%s positive case did not match: %q", rule.ID, tc.Input)
			}
		}
		for _, tc := range rule.Tests.Negative {
			if TestRuleAgainstInput(rule, tc.Input) {
				t.Fatalf("rule=%s negative case matched unexpectedly: %q", rule.ID, tc.Input)
			}
		}
	}
}
