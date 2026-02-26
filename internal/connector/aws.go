package connector

import (
	"context"
	"fmt"
	"os"
	"time"
)

type awsConnector struct{}

func newAWSConnector() Connector { return awsConnector{} }

func (awsConnector) Name() string        { return "aws" }
func (awsConnector) DisplayName() string { return "Amazon Web Services" }
func (awsConnector) SupportedRuleIDs() []string {
	return []string{"aws-access-key-id", "aws-secret-access-key"}
}

func (awsConnector) Validate(ctx context.Context, secret string) (*ValidationResult, error) {
	_ = ctx
	_ = secret
	return nil, fmt.Errorf("aws validation needs access-key-id + secret-access-key pair; use `connector test aws` for preflight")
}

func (awsConnector) Revoke(ctx context.Context, secret string) (*ActionResult, error) {
	_ = ctx
	_ = secret
	return &ActionResult{
		Success:    false,
		Message:    "manual revoke required: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
		ExecutedAt: time.Now().UTC(),
	}, nil
}

func (awsConnector) Rotate(ctx context.Context, secret string) (*RotationResult, error) {
	_ = ctx
	_ = secret
	return &RotationResult{
		OldKeyRevoked: false,
		NewKeyID:      "",
		StoredAt:      "manual rotation required in AWS IAM",
		ExecutedAt:    time.Now().UTC(),
	}, nil
}

func (awsConnector) PreflightCheck(ctx context.Context) (*PreflightResult, error) {
	_ = ctx
	missing := []PreflightItem{}
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		missing = append(missing, PreflightItem{
			Name:        "AWS_ACCESS_KEY_ID",
			Description: "Needed to call IAM and STS APIs",
			HowToFix:    "export AWS_ACCESS_KEY_ID=<value>",
		})
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		missing = append(missing, PreflightItem{
			Name:        "AWS_SECRET_ACCESS_KEY",
			Description: "Needed to call IAM and STS APIs",
			HowToFix:    "export AWS_SECRET_ACCESS_KEY=<value>",
		})
	}
	return &PreflightResult{Ready: len(missing) == 0, Missing: missing}, nil
}
