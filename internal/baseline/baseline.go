package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/peter941221/secrethawk/internal/model"
)

type File struct {
	Version     string  `json:"version"`
	GeneratedAt string  `json:"generated_at"`
	GeneratedBy string  `json:"generated_by"`
	Entries     []Entry `json:"entries"`
}

type Entry struct {
	FindingID string `json:"finding_id"`
	RuleID    string `json:"rule_id"`
	File      string `json:"file"`
	LineHash  string `json:"line_hash"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	AddedAt   string `json:"added_at"`
	AddedBy   string `json:"added_by"`
}

func ComputeLineHash(line string) string {
	sum := sha256.Sum256([]byte(line))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Load(path string) (File, error) {
	if path == "" {
		return Empty(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Empty(), nil
		}
		return File{}, err
	}

	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("parse baseline: %w", err)
	}
	if f.Version == "" {
		f.Version = "1"
	}
	return f, nil
}

func Empty() File {
	return File{Version: "1", Entries: []Entry{}}
}

func Save(path string, b File) error {
	if path == "" {
		return fmt.Errorf("baseline path required")
	}
	if b.Version == "" {
		b.Version = "1"
	}
	if b.GeneratedAt == "" {
		b.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if b.GeneratedBy == "" {
		b.GeneratedBy = "secrethawk"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func IsSuppressed(b File, f model.Finding) bool {
	for _, e := range b.Entries {
		if e.RuleID == f.RuleID && e.File == f.Location.File && e.LineHash == f.LineHash {
			return true
		}
	}
	return false
}

func UpsertEntries(base File, findings []model.Finding, status string, reason string, by string) File {
	out := base
	if out.Version == "" {
		out.Version = "1"
	}
	index := map[string]int{}
	for i, e := range out.Entries {
		key := e.RuleID + "|" + e.File + "|" + e.LineHash
		index[key] = i
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		entry := Entry{
			FindingID: f.ID,
			RuleID:    f.RuleID,
			File:      f.Location.File,
			LineHash:  f.LineHash,
			Status:    status,
			Reason:    reason,
			AddedAt:   now,
			AddedBy:   by,
		}
		key := entry.RuleID + "|" + entry.File + "|" + entry.LineHash
		if idx, ok := index[key]; ok {
			out.Entries[idx] = entry
			continue
		}
		out.Entries = append(out.Entries, entry)
		index[key] = len(out.Entries) - 1
	}
	out.GeneratedAt = now
	out.GeneratedBy = "secrethawk"
	return out
}
