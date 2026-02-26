package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type githubConnector struct{}

func newGitHubConnector() Connector { return githubConnector{} }

func (githubConnector) Name() string        { return "github" }
func (githubConnector) DisplayName() string { return "GitHub" }
func (githubConnector) SupportedRuleIDs() []string {
	return []string{
		"github-pat-classic",
		"github-pat-fine-grained",
		"github-oauth-token",
	}
}

func (githubConnector) Validate(ctx context.Context, secret string) (*ValidationResult, error) {
	if strings.Contains(secret, "...") {
		return nil, fmt.Errorf("redacted token cannot be validated")
	}
	url := "https://api.github.com/user"

	body, status, err := doJSONRequestWithRetry(ctx, "GET", url, secret)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return &ValidationResult{IsActive: false, Method: "github-user-api", Details: map[string]string{}, ValidatedAt: time.Now().UTC()}, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("github validate status=%d", status)
	}

	var payload struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return &ValidationResult{
		IsActive: true,
		Method:   "github-user-api",
		Details: map[string]string{
			"username": payload.Login,
		},
		ValidatedAt: time.Now().UTC(),
	}, nil
}

func (githubConnector) Revoke(ctx context.Context, secret string) (*ActionResult, error) {
	_ = ctx
	_ = secret
	return &ActionResult{Success: false, Message: "manual revoke: https://github.com/settings/tokens", ExecutedAt: time.Now().UTC()}, nil
}

func (githubConnector) Rotate(ctx context.Context, secret string) (*RotationResult, error) {
	_ = ctx
	_ = secret
	return &RotationResult{OldKeyRevoked: false, NewKeyID: "", StoredAt: "manual rotate: https://github.com/settings/tokens", ExecutedAt: time.Now().UTC()}, nil
}

func (githubConnector) PreflightCheck(ctx context.Context) (*PreflightResult, error) {
	_ = ctx
	return &PreflightResult{Ready: true, Missing: []PreflightItem{}}, nil
}

func doJSONRequestWithRetry(ctx context.Context, method string, url string, token string) ([]byte, int, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		status, body, err := doJSONRequest(ctx, method, url, token)
		if err == nil {
			return body, status, nil
		}
		lastErr = err
		time.Sleep(time.Duration(attempt*attempt) * 300 * time.Millisecond)
	}
	return nil, 0, lastErr
}

func doJSONRequest(ctx context.Context, method string, url string, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "secrethawk")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}
