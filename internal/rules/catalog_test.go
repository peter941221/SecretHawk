package rules

import "testing"

func TestBuiltInRuleCoverageForMVP(t *testing.T) {
	loaded, err := Load("../../rules", "")
	if err != nil {
		t.Fatal(err)
	}

	required := map[string]bool{
		"aws-access-key-id":       false,
		"aws-secret-access-key":   false,
		"github-pat-classic":      false,
		"github-pat-fine-grained": false,
		"github-oauth-token":      false,
		"slack-bot-token":         false,
		"slack-webhook-url":       false,
		"stripe-api-key":          false,
		"private-key-header":      false,
	}

	for _, r := range loaded {
		if _, ok := required[r.ID]; ok {
			required[r.ID] = true
		}
	}

	for id, ok := range required {
		if !ok {
			t.Fatalf("missing built-in rule: %s", id)
		}
	}
}
