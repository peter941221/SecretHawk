package cisync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestSplitRepo(t *testing.T) {
	owner, repo, err := splitRepo("octo/hello")
	if err != nil {
		t.Fatal(err)
	}
	if owner != "octo" || repo != "hello" {
		t.Fatalf("unexpected split: %s/%s", owner, repo)
	}

	if _, _, err := splitRepo("bad-format"); err == nil {
		t.Fatal("expected error for invalid repo format")
	}
}

func TestSyncRepoSecretsSuccess(t *testing.T) {
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])

	seenPut := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-123" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets/public-key") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "kid-1", "key": pubB64})
			return
		}

		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/actions/secrets/") {
			var req putSecretRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.KeyID != "kid-1" || req.EncryptedValue == "" {
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			if _, err := base64.StdEncoding.DecodeString(req.EncryptedValue); err != nil {
				http.Error(w, "encrypted value not base64", http.StatusBadRequest)
				return
			}
			seenPut[r.URL.Path] = true
			w.WriteHeader(http.StatusCreated)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewGitHubActionsClient("token-123", server.Client())
	client.BaseURL = server.URL

	res, err := client.SyncRepoSecrets(context.Background(), "owner/repo", map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIA1111222233334444",
		"EMPTY":             "",
		"AWS_SECRET":        "xyz",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Attempted != 2 || res.Updated != 2 || res.Skipped != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !seenPut["/repos/owner/repo/actions/secrets/AWS_ACCESS_KEY_ID"] {
		t.Fatal("expected secret AWS_ACCESS_KEY_ID to be pushed")
	}
	if !seenPut["/repos/owner/repo/actions/secrets/AWS_SECRET"] {
		t.Fatal("expected secret AWS_SECRET to be pushed")
	}
}

func TestSyncRepoSecretsMissingToken(t *testing.T) {
	client := NewGitHubActionsClient("", nil)
	_, err := client.SyncRepoSecrets(context.Background(), "owner/repo", map[string]string{"A": "B"})
	if err == nil {
		t.Fatal("expected token error")
	}
}
