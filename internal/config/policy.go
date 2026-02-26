package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version   string         `yaml:"version"`
	Scan      ScanPolicy     `yaml:"scan"`
	Allowlist Allowlist      `yaml:"allowlist"`
	Severity  SeverityPolicy `yaml:"severity"`
}

type ScanPolicy struct {
	DefaultMode   string   `yaml:"default_mode"`
	ExcludePaths  []string `yaml:"exclude_paths"`
	MaxFileSizeKB int      `yaml:"max_file_size_kb"`
}

type Allowlist struct {
	Patterns []AllowPattern `yaml:"patterns"`
	Paths    []AllowPath    `yaml:"paths"`
	Commits  []AllowCommit  `yaml:"commits"`
}

type AllowPattern struct {
	Regex  string `yaml:"regex"`
	Reason string `yaml:"reason"`
}

type AllowPath struct {
	Pattern string   `yaml:"pattern"`
	Rules   []string `yaml:"rules"`
	Reason  string   `yaml:"reason"`
}

type AllowCommit struct {
	SHA    string `yaml:"sha"`
	Reason string `yaml:"reason"`
}

type SeverityPolicy struct {
	BlockOn string `yaml:"block_on"`
}

func DefaultPolicy() Policy {
	return Policy{
		Version: "1",
		Scan: ScanPolicy{
			DefaultMode:   "directory",
			ExcludePaths:  []string{".git/**", "vendor/**", "node_modules/**"},
			MaxFileSizeKB: 500,
		},
		Severity: SeverityPolicy{BlockOn: "high"},
	}
}

func LoadPolicy(path string) (Policy, error) {
	policy := DefaultPolicy()
	if path == "" {
		return policy, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return policy, nil
		}
		return Policy{}, err
	}

	if err := yaml.Unmarshal(data, &policy); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}

	if policy.Version == "" {
		policy.Version = "1"
	}
	if policy.Scan.MaxFileSizeKB <= 0 {
		policy.Scan.MaxFileSizeKB = 500
	}
	if len(policy.Scan.ExcludePaths) == 0 {
		policy.Scan.ExcludePaths = DefaultPolicy().Scan.ExcludePaths
	}
	if policy.Severity.BlockOn == "" {
		policy.Severity.BlockOn = DefaultPolicy().Severity.BlockOn
	}

	return policy, nil
}

func ValidatePolicy(path string) error {
	policy, err := LoadPolicy(path)
	if err != nil {
		return err
	}
	if policy.Version != "1" {
		return fmt.Errorf("unsupported policy version: %s", policy.Version)
	}
	if policy.Severity.BlockOn == "" {
		return fmt.Errorf("severity.block_on is required")
	}
	return nil
}
