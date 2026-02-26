package connector

import (
	"context"
	"time"
)

type stripeConnector struct{}

func newStripeConnector() Connector { return stripeConnector{} }

func (stripeConnector) Name() string               { return "stripe" }
func (stripeConnector) DisplayName() string        { return "Stripe" }
func (stripeConnector) SupportedRuleIDs() []string { return []string{"stripe-api-key"} }

func (stripeConnector) Validate(ctx context.Context, secret string) (*ValidationResult, error) {
	_ = ctx
	_ = secret
	return &ValidationResult{IsActive: false, Method: "manual", Details: map[string]string{"hint": "Validate via Stripe dashboard/API"}, ValidatedAt: time.Now().UTC()}, nil
}

func (stripeConnector) Revoke(ctx context.Context, secret string) (*ActionResult, error) {
	_ = ctx
	_ = secret
	return &ActionResult{Success: false, Message: "manual revoke: https://dashboard.stripe.com/apikeys", ExecutedAt: time.Now().UTC()}, nil
}

func (stripeConnector) Rotate(ctx context.Context, secret string) (*RotationResult, error) {
	_ = ctx
	_ = secret
	return &RotationResult{OldKeyRevoked: false, StoredAt: "manual rotate in Stripe dashboard", ExecutedAt: time.Now().UTC()}, nil
}

func (stripeConnector) PreflightCheck(ctx context.Context) (*PreflightResult, error) {
	_ = ctx
	return &PreflightResult{Ready: true, Missing: []PreflightItem{}}, nil
}
