package connector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type fakeSTSClient struct {
	output *sts.GetCallerIdentityOutput
	err    error
	calls  int
}

func (f *fakeSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.calls++
	_ = ctx
	_ = params
	_ = optFns
	if f.err != nil {
		return nil, f.err
	}
	return f.output, nil
}

type fakeIAMClient struct {
	listOut   *iam.ListAccessKeysOutput
	createOut *iam.CreateAccessKeyOutput
	updateErr error
	deleteErr error

	updated []string
	deleted []string
}

func (f *fakeIAMClient) ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	_ = ctx
	_ = params
	_ = optFns
	if f.listOut == nil {
		return &iam.ListAccessKeysOutput{}, nil
	}
	return f.listOut, nil
}

func (f *fakeIAMClient) UpdateAccessKey(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
	_ = ctx
	_ = optFns
	if params != nil && params.AccessKeyId != nil {
		f.updated = append(f.updated, aws.ToString(params.AccessKeyId))
	}
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return &iam.UpdateAccessKeyOutput{}, nil
}

func (f *fakeIAMClient) CreateAccessKey(ctx context.Context, params *iam.CreateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	_ = ctx
	_ = params
	_ = optFns
	if f.createOut == nil {
		return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{AccessKeyId: aws.String("AKIA1111222233334444")}}, nil
	}
	return f.createOut, nil
}

func (f *fakeIAMClient) DeleteAccessKey(ctx context.Context, params *iam.DeleteAccessKeyInput, optFns ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	_ = ctx
	_ = optFns
	if params != nil && params.AccessKeyId != nil {
		f.deleted = append(f.deleted, aws.ToString(params.AccessKeyId))
	}
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return &iam.DeleteAccessKeyOutput{}, nil
}

func TestIAMUserNameFromARN(t *testing.T) {
	user, err := iamUserNameFromARN("arn:aws:iam::123456789012:user/dev/team/deploy-bot")
	if err != nil {
		t.Fatal(err)
	}
	if user != "deploy-bot" {
		t.Fatalf("unexpected user: %s", user)
	}
}

func TestIAMUserNameFromARNRejectsAssumedRole(t *testing.T) {
	_, err := iamUserNameFromARN("arn:aws:sts::123456789012:assumed-role/Admin/session")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAWSPreflightMissingEnv(t *testing.T) {
	c := awsConnector{env: func(string) string { return "" }}
	pf, err := c.PreflightCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pf.Ready {
		t.Fatal("expected preflight not ready")
	}
	if len(pf.Missing) < 2 {
		t.Fatalf("expected missing env vars, got %+v", pf.Missing)
	}
}

func TestAWSValidateActive(t *testing.T) {
	fakeSTS := &fakeSTSClient{output: &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"),
		Arn:     aws.String("arn:aws:iam::123456789012:user/deploy-bot"),
		UserId:  aws.String("AIDATESTUSER"),
	}}
	c := awsConnector{
		newClients: func(ctx context.Context) (stsAPI, iamAPI, error) {
			return fakeSTS, &fakeIAMClient{}, nil
		},
		now: func() time.Time { return time.Unix(1, 0).UTC() },
		env: func(k string) string {
			switch k {
			case "AWS_ACCESS_KEY_ID":
				return "AKIA1111222233334444"
			case "AWS_SECRET_ACCESS_KEY":
				return "secret"
			default:
				return ""
			}
		},
	}

	res, err := c.Validate(context.Background(), "AKIA1111222233334444")
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsActive {
		t.Fatal("expected active validation")
	}
	if res.Method != "aws-sts-get-caller-identity" {
		t.Fatalf("unexpected method: %s", res.Method)
	}
}

func TestAWSValidateMismatchedKey(t *testing.T) {
	c := awsConnector{
		newClients: func(ctx context.Context) (stsAPI, iamAPI, error) {
			return &fakeSTSClient{}, &fakeIAMClient{}, nil
		},
		now: func() time.Time { return time.Now().UTC() },
		env: func(k string) string {
			switch k {
			case "AWS_ACCESS_KEY_ID":
				return "AKIA1111222233334444"
			case "AWS_SECRET_ACCESS_KEY":
				return "secret"
			default:
				return ""
			}
		},
	}
	_, err := c.Validate(context.Background(), "AKIA9999888877776666")
	if err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestAWSRotateSuccess(t *testing.T) {
	fakeSTS := &fakeSTSClient{output: &sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/deploy-bot")}}
	fakeIAM := &fakeIAMClient{
		listOut:   &iam.ListAccessKeysOutput{AccessKeyMetadata: []iamtypes.AccessKeyMetadata{{AccessKeyId: aws.String("AKIA1111222233334444")}}},
		createOut: &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{AccessKeyId: aws.String("AKIA5555666677778888")}},
	}
	c := awsConnector{
		newClients: func(ctx context.Context) (stsAPI, iamAPI, error) {
			return fakeSTS, fakeIAM, nil
		},
		now: func() time.Time { return time.Unix(2, 0).UTC() },
		env: func(k string) string {
			switch k {
			case "AWS_ACCESS_KEY_ID":
				return "AKIA1111222233334444"
			case "AWS_SECRET_ACCESS_KEY":
				return "secret"
			default:
				return ""
			}
		},
	}

	res, err := c.Rotate(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OldKeyRevoked {
		t.Fatal("expected old key revoked")
	}
	if res.NewKeyID != "AKIA5555666677778888" {
		t.Fatalf("unexpected new key id: %s", res.NewKeyID)
	}
	if len(fakeIAM.updated) != 1 || fakeIAM.updated[0] != "AKIA1111222233334444" {
		t.Fatalf("unexpected updated keys: %+v", fakeIAM.updated)
	}
}

func TestAWSRotateRollbackOnDeactivateFailure(t *testing.T) {
	fakeSTS := &fakeSTSClient{output: &sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:iam::123456789012:user/deploy-bot")}}
	fakeIAM := &fakeIAMClient{
		listOut:   &iam.ListAccessKeysOutput{AccessKeyMetadata: []iamtypes.AccessKeyMetadata{{AccessKeyId: aws.String("AKIA1111222233334444")}}},
		createOut: &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{AccessKeyId: aws.String("AKIA5555666677778888")}},
		updateErr: errors.New("update failed"),
	}
	c := awsConnector{
		newClients: func(ctx context.Context) (stsAPI, iamAPI, error) {
			return fakeSTS, fakeIAM, nil
		},
		now: func() time.Time { return time.Now().UTC() },
		env: func(k string) string {
			switch k {
			case "AWS_ACCESS_KEY_ID":
				return "AKIA1111222233334444"
			case "AWS_SECRET_ACCESS_KEY":
				return "secret"
			default:
				return ""
			}
		},
	}

	_, err := c.Rotate(context.Background(), "")
	if err == nil {
		t.Fatal("expected rotate error")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rollback hint, got: %v", err)
	}
	if len(fakeIAM.deleted) != 1 || fakeIAM.deleted[0] != "AKIA5555666677778888" {
		t.Fatalf("expected new key rollback delete, got %+v", fakeIAM.deleted)
	}
}

type fakeAPIError struct {
	code string
	msg  string
}

func (e fakeAPIError) ErrorCode() string    { return e.code }
func (e fakeAPIError) ErrorMessage() string { return e.msg }
func (e fakeAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultClient
}
func (e fakeAPIError) Error() string { return e.msg }

func TestIsAWSAuthFailure(t *testing.T) {
	if !isAWSAuthFailure(fakeAPIError{code: "InvalidClientTokenId", msg: "bad"}) {
		t.Fatal("expected auth failure")
	}
	if isAWSAuthFailure(errors.New("other")) {
		t.Fatal("did not expect auth failure")
	}
}
