package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type githubConnector struct {
	baseURL    string
	httpClient *http.Client
	env        func(string) string
	now        func() time.Time
	sleep      func(time.Duration)
}

func newGitHubConnector() Connector {
	return githubConnector{
		baseURL:    "https://api.github.com",
		httpClient: &http.Client{Timeout: 10 * time.Second},
		env:        os.Getenv,
		now:        func() time.Time { return time.Now().UTC() },
		sleep:      time.Sleep,
	}
}

func (githubConnector) Name() string        { return "github" }
func (githubConnector) DisplayName() string { return "GitHub" }
func (githubConnector) SupportedRuleIDs() []string {
	return []string{
		"github-pat-classic",
		"github-pat-fine-grained",
		"github-oauth-token",
	}
}

func (c githubConnector) Validate(ctx context.Context, secret string) (*ValidationResult, error) {
	if strings.Contains(secret, "...") {
		return nil, fmt.Errorf("redacted token cannot be validated")
	}
	status, body, err := c.doTokenRequestWithRetry(ctx, http.MethodGet, c.baseURL+"/user", secret, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return &ValidationResult{IsActive: false, Method: "github-user-api", Details: map[string]string{}, ValidatedAt: c.now()}, nil
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
		ValidatedAt: c.now(),
	}, nil
}

func (c githubConnector) Revoke(ctx context.Context, secret string) (*ActionResult, error) {
	if strings.Contains(secret, "...") {
		return &ActionResult{Success: false, Message: "redacted token cannot be revoked automatically", ExecutedAt: c.now()}, nil
	}

	clientID := strings.TrimSpace(c.env("GITHUB_APP_CLIENT_ID"))
	clientSecret := strings.TrimSpace(c.env("GITHUB_APP_CLIENT_SECRET"))
	if clientID == "" || clientSecret == "" {
		return &ActionResult{Success: false, Message: "manual revoke: https://github.com/settings/tokens (or configure GITHUB_APP_CLIENT_ID + GITHUB_APP_CLIENT_SECRET for API revoke)", ExecutedAt: c.now()}, nil
	}

	url := fmt.Sprintf("%s/applications/%s/token", strings.TrimRight(c.baseURL, "/"), clientID)
	payload := map[string]string{"access_token": secret}
	body, _ := json.Marshal(payload)
	status, resp, err := c.doAppRequestWithRetry(ctx, http.MethodDelete, url, clientID, clientSecret, body)
	if err != nil {
		return nil, err
	}

	switch status {
	case http.StatusNoContent:
		return &ActionResult{Success: true, Message: "token revoked via GitHub Applications API", ExecutedAt: c.now()}, nil
	case http.StatusNotFound:
		return &ActionResult{Success: true, Message: "token already revoked or not found", ExecutedAt: c.now()}, nil
	default:
		return &ActionResult{Success: false, Message: fmt.Sprintf("github revoke failed status=%d body=%s", status, strings.TrimSpace(string(resp))), ExecutedAt: c.now()}, nil
	}
}

func (c githubConnector) Rotate(ctx context.Context, secret string) (*RotationResult, error) {
	_ = ctx
	_ = secret
	return &RotationResult{OldKeyRevoked: false, NewKeyID: "", StoredAt: "manual rotate: https://github.com/settings/tokens", ExecutedAt: c.now()}, nil
}

func (githubConnector) PreflightCheck(ctx context.Context) (*PreflightResult, error) {
	_ = ctx
	return &PreflightResult{Ready: true, Missing: []PreflightItem{}}, nil
}

func (c githubConnector) doTokenRequestWithRetry(ctx context.Context, method string, url string, token string, payload []byte) (int, []byte, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		status, body, err := c.doTokenRequest(ctx, method, url, token, payload)
		if err == nil {
			return status, body, nil
		}
		lastErr = err
		c.sleep(time.Duration(attempt*attempt) * 300 * time.Millisecond)
	}
	return 0, nil, lastErr
}

func (c githubConnector) doTokenRequest(ctx context.Context, method string, url string, token string, payload []byte) (int, []byte, error) {
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "secrethawk")
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
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

func (c githubConnector) doAppRequestWithRetry(ctx context.Context, method string, url string, clientID string, clientSecret string, payload []byte) (int, []byte, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		status, body, err := c.doAppRequest(ctx, method, url, clientID, clientSecret, payload)
		if err == nil {
			return status, body, nil
		}
		lastErr = err
		c.sleep(time.Duration(attempt*attempt) * 300 * time.Millisecond)
	}
	return 0, nil, lastErr
}

func (c githubConnector) doAppRequest(ctx context.Context, method string, url string, clientID string, clientSecret string, payload []byte) (int, []byte, error) {
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "secrethawk")
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
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
