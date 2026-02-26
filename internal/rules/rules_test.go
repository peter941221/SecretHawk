package rules

import "testing"

func TestAwsRuleMatchesSample(t *testing.T) {
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
	line := "aws_key = \"AKIA3EXAMPLE7JKXQ4F7\""
	if !MatchRule(rule, line) {
		t.Fatal("expected regex match")
	}
}
