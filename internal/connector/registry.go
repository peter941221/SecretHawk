package connector

import (
	"context"
	"fmt"
)

func Registry() []Connector {
	return []Connector{
		newAWSConnector(),
		newGitHubConnector(),
	}
}

func ByName(name string) (Connector, error) {
	for _, c := range Registry() {
		if c.Name() == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("connector not found: %s", name)
}

func FindByRuleID(ruleID string) Connector {
	for _, c := range Registry() {
		for _, rid := range c.SupportedRuleIDs() {
			if rid == ruleID {
				return c
			}
		}
	}
	return nil
}

func ValidateWithConnector(ctx context.Context, c Connector, secret string) (string, map[string]any) {
	result, err := c.Validate(ctx, secret)
	if err != nil {
		return "error", map[string]any{"error": err.Error()}
	}
	status := "inactive"
	if result.IsActive {
		status = "active"
	}
	out := map[string]any{}
	for k, v := range result.Details {
		out[k] = v
	}
	out["method"] = result.Method
	return status, out
}
