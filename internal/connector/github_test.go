package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGitHubValidateActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "token token-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "octocat"})
	}))
	defer server.Close()

	c := githubConnector{
		baseURL:    server.URL,
		httpClient: server.Client(),
		env:        func(string) string { return "" },
		now:        func() time.Time { return time.Unix(1, 0).UTC() },
		sleep:      func(time.Duration) {},
	}

	res, err := c.Validate(context.Background(), "token-123")
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsActive || res.Details["username"] != "octocat" {
		t.Fatalf("unexpected validation result: %+v", res)
	}
}

func TestGitHubRevokeManualWhenAppCredsMissing(t *testing.T) {
	c := githubConnector{
		baseURL:    "https://api.github.com",
		httpClient: http.DefaultClient,
		env:        func(string) string { return "" },
		now:        func() time.Time { return time.Unix(1, 0).UTC() },
		sleep:      func(time.Duration) {},
	}

	res, err := c.Revoke(context.Background(), "token-123")
	if err != nil {
		t.Fatal(err)
	}
	if res.Success {
		t.Fatal("expected manual revoke fallback")
	}
	if !strings.Contains(res.Message, "manual revoke") {
		t.Fatalf("unexpected message: %s", res.Message)
	}
}

func TestGitHubRevokeViaApplicationsAPI(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/applications/app-123/token" {
			http.NotFound(w, r)
			return
		}
		called = true
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			http.Error(w, "missing basic auth", http.StatusUnauthorized)
			return
		}
		decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if string(decoded) != "app-123:app-secret" {
			http.Error(w, "bad creds", http.StatusUnauthorized)
			return
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload["access_token"] != "token-123" {
			http.Error(w, "wrong token payload", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c := githubConnector{
		baseURL:    server.URL,
		httpClient: server.Client(),
		env: func(k string) string {
			switch k {
			case "GITHUB_APP_CLIENT_ID":
				return "app-123"
			case "GITHUB_APP_CLIENT_SECRET":
				return "app-secret"
			default:
				return ""
			}
		},
		now:   func() time.Time { return time.Unix(1, 0).UTC() },
		sleep: func(time.Duration) {},
	}

	res, err := c.Revoke(context.Background(), "token-123")
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected applications API to be called")
	}
	if !res.Success {
		t.Fatalf("expected revoke success, got %+v", res)
	}
}
