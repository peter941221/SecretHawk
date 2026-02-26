package connector

import (
	"context"
	"time"
)

// Connector defines how a secret backend validates/revokes/rotates credentials.
type Connector interface {
	Name() string
	DisplayName() string
	SupportedRuleIDs() []string
	Validate(ctx context.Context, secret string) (*ValidationResult, error)
	Revoke(ctx context.Context, secret string) (*ActionResult, error)
	Rotate(ctx context.Context, secret string) (*RotationResult, error)
	PreflightCheck(ctx context.Context) (*PreflightResult, error)
}

type ValidationResult struct {
	IsActive    bool
	Method      string
	Details     map[string]string
	ValidatedAt time.Time
}

type ActionResult struct {
	Success    bool
	Message    string
	ExecutedAt time.Time
}

type RotationResult struct {
	OldKeyRevoked bool
	NewKeyID      string
	StoredAt      string
	ExecutedAt    time.Time
}

type PreflightResult struct {
	Ready   bool
	Missing []PreflightItem
}

type PreflightItem struct {
	Name        string
	Description string
	HowToFix    string
}
