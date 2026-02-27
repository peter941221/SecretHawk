package cisync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

type GitHubActionsClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

type SyncResult struct {
	Attempted int
	Updated   int
	Skipped   int
}

type publicKeyResponse struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

type putSecretRequest struct {
	EncryptedValue string `json:"encrypted_value"`
	KeyID          string `json:"key_id"`
}

func NewGitHubActionsClient(token string, httpClient *http.Client) *GitHubActionsClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &GitHubActionsClient{
		BaseURL:    "https://api.github.com",
		Token:      token,
		HTTPClient: httpClient,
	}
}

func (c *GitHubActionsClient) SyncRepoSecrets(ctx context.Context, repo string, values map[string]string) (SyncResult, error) {
	if strings.TrimSpace(c.Token) == "" {
		return SyncResult{}, fmt.Errorf("github token is required")
	}
	owner, name, err := splitRepo(repo)
	if err != nil {
		return SyncResult{}, err
	}

	pk, err := c.getRepoPublicKey(ctx, owner, name)
	if err != nil {
		return SyncResult{}, err
	}

	result := SyncResult{}
	for k, v := range values {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			result.Skipped++
			continue
		}
		result.Attempted++
		encrypted, err := encryptForGitHub(pk.Key, v)
		if err != nil {
			return result, err
		}
		if err := c.putRepoSecret(ctx, owner, name, k, putSecretRequest{EncryptedValue: encrypted, KeyID: pk.KeyID}); err != nil {
			return result, err
		}
		result.Updated++
	}
	return result, nil
}

func (c *GitHubActionsClient) getRepoPublicKey(ctx context.Context, owner string, repo string) (*publicKeyResponse, error) {
	u := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/public-key", strings.TrimRight(c.BaseURL, "/"), url.PathEscape(owner), url.PathEscape(repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github public key request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out publicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Key == "" || out.KeyID == "" {
		return nil, fmt.Errorf("github public key response incomplete")
	}
	return &out, nil
}

func (c *GitHubActionsClient) putRepoSecret(ctx context.Context, owner string, repo string, secretName string, payload putSecretRequest) error {
	u := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/%s", strings.TrimRight(c.BaseURL, "/"), url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(secretName))
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		resBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github put secret failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(resBody)))
	}
	return nil
}

func splitRepo(v string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(v), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid github repo format, want owner/repo")
	}
	return parts[0], parts[1], nil
}

func encryptForGitHub(base64PublicKey string, secretValue string) (string, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return "", fmt.Errorf("decode github public key: %w", err)
	}
	if len(pkBytes) != 32 {
		return "", fmt.Errorf("unexpected github public key length: %d", len(pkBytes))
	}
	var pk [32]byte
	copy(pk[:], pkBytes)

	cipher, err := box.SealAnonymous(nil, []byte(secretValue), &pk, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipher), nil
}
