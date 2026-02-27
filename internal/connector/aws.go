package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type stsAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type iamAPI interface {
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	UpdateAccessKey(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error)
	CreateAccessKey(ctx context.Context, params *iam.CreateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(ctx context.Context, params *iam.DeleteAccessKeyInput, optFns ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}

type awsConnector struct {
	newClients func(ctx context.Context) (stsAPI, iamAPI, error)
	now        func() time.Time
	env        func(string) string
}

var awsKeyIDPattern = regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`)

func newAWSConnector() Connector {
	return awsConnector{
		newClients: defaultAWSClients,
		now:        func() time.Time { return time.Now().UTC() },
		env:        os.Getenv,
	}
}

func (awsConnector) Name() string        { return "aws" }
func (awsConnector) DisplayName() string { return "Amazon Web Services" }
func (awsConnector) SupportedRuleIDs() []string {
	return []string{"aws-access-key-id", "aws-secret-access-key"}
}

func defaultAWSClients(ctx context.Context) (stsAPI, iamAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(defaultAWSRegion()))
	if err != nil {
		return nil, nil, err
	}
	return sts.NewFromConfig(cfg), iam.NewFromConfig(cfg), nil
}

func defaultAWSRegion() string {
	if v := os.Getenv("AWS_REGION"); strings.TrimSpace(v) != "" {
		return v
	}
	if v := os.Getenv("AWS_DEFAULT_REGION"); strings.TrimSpace(v) != "" {
		return v
	}
	return "us-east-1"
}

func (c awsConnector) Validate(ctx context.Context, secret string) (*ValidationResult, error) {
	if pf, err := c.PreflightCheck(ctx); err != nil {
		return nil, err
	} else if !pf.Ready {
		return nil, fmt.Errorf("aws preflight failed: missing %s", strings.Join(missingNames(pf.Missing), ", "))
	}

	providedKey := normalizeAWSKeyID(secret)
	envKey := normalizeAWSKeyID(c.env("AWS_ACCESS_KEY_ID"))
	if providedKey != "" && envKey != "" && providedKey != envKey {
		return nil, fmt.Errorf("provided key does not match current AWS_ACCESS_KEY_ID")
	}

	stsClient, _, err := c.newClients(ctx)
	if err != nil {
		return nil, err
	}

	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if isAWSAuthFailure(err) {
			return &ValidationResult{
				IsActive:    false,
				Method:      "aws-sts-get-caller-identity",
				Details:     map[string]string{"reason": "authentication-failed"},
				ValidatedAt: c.now(),
			}, nil
		}
		return nil, err
	}

	return &ValidationResult{
		IsActive: true,
		Method:   "aws-sts-get-caller-identity",
		Details: map[string]string{
			"account": aws.ToString(out.Account),
			"arn":     aws.ToString(out.Arn),
			"user_id": aws.ToString(out.UserId),
		},
		ValidatedAt: c.now(),
	}, nil
}

func (c awsConnector) Revoke(ctx context.Context, secret string) (*ActionResult, error) {
	if pf, err := c.PreflightCheck(ctx); err != nil {
		return nil, err
	} else if !pf.Ready {
		return &ActionResult{
			Success:    false,
			Message:    fmt.Sprintf("aws preflight failed: missing %s", strings.Join(missingNames(pf.Missing), ", ")),
			ExecutedAt: c.now(),
		}, nil
	}

	stsClient, iamClient, err := c.newClients(ctx)
	if err != nil {
		return nil, err
	}

	userName, err := currentIAMUserName(ctx, stsClient)
	if err != nil {
		return &ActionResult{
			Success:    false,
			Message:    fmt.Sprintf("cannot resolve IAM user for revoke: %v", err),
			ExecutedAt: c.now(),
		}, nil
	}

	oldKey := normalizeAWSKeyID(secret)
	if oldKey == "" {
		oldKey = normalizeAWSKeyID(c.env("AWS_ACCESS_KEY_ID"))
	}
	if oldKey == "" {
		return &ActionResult{Success: false, Message: "missing access key id to revoke", ExecutedAt: c.now()}, nil
	}

	_, err = iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		UserName:    aws.String(userName),
		AccessKeyId: aws.String(oldKey),
		Status:      iamtypes.StatusTypeInactive,
	})
	if err != nil {
		return &ActionResult{Success: false, Message: fmt.Sprintf("revoke failed: %v", err), ExecutedAt: c.now()}, nil
	}

	return &ActionResult{Success: true, Message: "access key set to Inactive", ExecutedAt: c.now()}, nil
}

func (c awsConnector) Rotate(ctx context.Context, secret string) (*RotationResult, error) {
	if pf, err := c.PreflightCheck(ctx); err != nil {
		return nil, err
	} else if !pf.Ready {
		return nil, fmt.Errorf("aws preflight failed: missing %s", strings.Join(missingNames(pf.Missing), ", "))
	}

	stsClient, iamClient, err := c.newClients(ctx)
	if err != nil {
		return nil, err
	}

	userName, err := currentIAMUserName(ctx, stsClient)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve IAM user for rotation: %w", err)
	}

	oldKey := normalizeAWSKeyID(secret)
	if oldKey == "" {
		oldKey = normalizeAWSKeyID(c.env("AWS_ACCESS_KEY_ID"))
	}

	listOut, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(userName)})
	if err != nil {
		return nil, err
	}

	if oldKey == "" {
		for _, m := range listOut.AccessKeyMetadata {
			if m.AccessKeyId != nil {
				oldKey = aws.ToString(m.AccessKeyId)
				break
			}
		}
	}

	if oldKey != "" && !containsAccessKeyID(listOut.AccessKeyMetadata, oldKey) {
		return nil, fmt.Errorf("target old key id not found for IAM user")
	}

	createOut, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(userName)})
	if err != nil {
		return nil, err
	}
	newKeyID := ""
	if createOut.AccessKey != nil && createOut.AccessKey.AccessKeyId != nil {
		newKeyID = aws.ToString(createOut.AccessKey.AccessKeyId)
	}

	oldRevoked := false
	if oldKey != "" && oldKey != newKeyID {
		_, err = iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
			UserName:    aws.String(userName),
			AccessKeyId: aws.String(oldKey),
			Status:      iamtypes.StatusTypeInactive,
		})
		if err != nil {
			if newKeyID != "" {
				_, _ = iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: aws.String(userName), AccessKeyId: aws.String(newKeyID)})
			}
			return nil, fmt.Errorf("failed to deactivate old key (new key rolled back): %w", err)
		}
		oldRevoked = true
	}

	return &RotationResult{
		OldKeyRevoked: oldRevoked,
		NewKeyID:      newKeyID,
		StoredAt:      "new secret value returned by AWS API but intentionally not printed; store in secret manager",
		ExecutedAt:    c.now(),
	}, nil
}

func (c awsConnector) PreflightCheck(ctx context.Context) (*PreflightResult, error) {
	_ = ctx
	missing := []PreflightItem{}
	if strings.TrimSpace(c.env("AWS_ACCESS_KEY_ID")) == "" {
		missing = append(missing, PreflightItem{
			Name:        "AWS_ACCESS_KEY_ID",
			Description: "Needed to call IAM and STS APIs",
			HowToFix:    "export AWS_ACCESS_KEY_ID=<value>",
		})
	}
	if strings.TrimSpace(c.env("AWS_SECRET_ACCESS_KEY")) == "" {
		missing = append(missing, PreflightItem{
			Name:        "AWS_SECRET_ACCESS_KEY",
			Description: "Needed to call IAM and STS APIs",
			HowToFix:    "export AWS_SECRET_ACCESS_KEY=<value>",
		})
	}
	return &PreflightResult{Ready: len(missing) == 0, Missing: missing}, nil
}

func missingNames(items []PreflightItem) []string {
	names := make([]string, 0, len(items))
	for _, m := range items {
		names = append(names, m.Name)
	}
	return names
}

func normalizeAWSKeyID(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	if awsKeyIDPattern.MatchString(v) {
		return v
	}
	return ""
}

func currentIAMUserName(ctx context.Context, stsClient stsAPI) (string, error) {
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return iamUserNameFromARN(aws.ToString(out.Arn))
}

func iamUserNameFromARN(arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return "", fmt.Errorf("invalid arn: %s", arn)
	}
	resource := parts[5]
	if resource == "root" {
		return "", fmt.Errorf("root principal does not support access key rotation")
	}
	if strings.HasPrefix(resource, "assumed-role/") {
		return "", fmt.Errorf("assumed-role principal does not support IAM access key rotation")
	}
	if !strings.HasPrefix(resource, "user/") {
		return "", fmt.Errorf("principal is not IAM user: %s", resource)
	}
	userPath := strings.TrimPrefix(resource, "user/")
	chunks := strings.Split(strings.Trim(userPath, "/"), "/")
	if len(chunks) == 0 || strings.TrimSpace(chunks[len(chunks)-1]) == "" {
		return "", fmt.Errorf("cannot parse user name from arn")
	}
	return chunks[len(chunks)-1], nil
}

func containsAccessKeyID(meta []iamtypes.AccessKeyMetadata, keyID string) bool {
	for _, m := range meta {
		if m.AccessKeyId != nil && aws.ToString(m.AccessKeyId) == keyID {
			return true
		}
	}
	return false
}

func isAWSAuthFailure(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "InvalidClientTokenId", "SignatureDoesNotMatch", "AuthFailure", "UnrecognizedClientException", "ExpiredToken", "InvalidSignatureException":
		return true
	default:
		return false
	}
}
