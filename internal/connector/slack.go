package connector

import (
	"context"
	"time"
)

type slackConnector struct{}

func newSlackConnector() Connector { return slackConnector{} }

func (slackConnector) Name() string        { return "slack" }
func (slackConnector) DisplayName() string { return "Slack" }
func (slackConnector) SupportedRuleIDs() []string {
	return []string{"slack-bot-token", "slack-webhook-url"}
}

func (slackConnector) Validate(ctx context.Context, secret string) (*ValidationResult, error) {
	_ = ctx
	_ = secret
	return &ValidationResult{IsActive: false, Method: "manual", Details: map[string]string{"hint": "Use Slack auth.test or webhook test manually"}, ValidatedAt: time.Now().UTC()}, nil
}

func (slackConnector) Revoke(ctx context.Context, secret string) (*ActionResult, error) {
	_ = ctx
	_ = secret
	return &ActionResult{Success: false, Message: "manual revoke: https://api.slack.com/apps", ExecutedAt: time.Now().UTC()}, nil
}

func (slackConnector) Rotate(ctx context.Context, secret string) (*RotationResult, error) {
	_ = ctx
	_ = secret
	return &RotationResult{OldKeyRevoked: false, StoredAt: "manual rotate in Slack app settings", ExecutedAt: time.Now().UTC()}, nil
}

func (slackConnector) PreflightCheck(ctx context.Context) (*PreflightResult, error) {
	_ = ctx
	return &PreflightResult{Ready: true, Missing: []PreflightItem{}}, nil
}
