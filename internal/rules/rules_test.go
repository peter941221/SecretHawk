package rules

import "testing"

func TestAwsRuleMatchesAllBundledCases(t *testing.T) {
	rs, err := Load("../../rules", "")
	if err != nil {
		t.Fatal(err)
	}
	var rule Rule
	found := false
	for _, r := range rs {
		if r.ID == "aws-access-key-id" {
			rule = r
			found = true
			break
		}
	}
	if !found {
		t.Fatal("rule not found")
	}

	for _, tc := range rule.Tests.Positive {
		if !MatchRule(rule, tc.Input) {
			t.Fatalf("positive case did not match: %q", tc.Input)
		}
	}
	for _, tc := range rule.Tests.Negative {
		if MatchRule(rule, tc.Input) {
			t.Fatalf("negative case matched unexpectedly: %q", tc.Input)
		}
	}
}
