package model

import "time"

// FindingReport is the top-level JSON output payload.
type FindingReport struct {
	Schema   string    `json:"$schema,omitempty"`
	Findings []Finding `json:"findings"`
	Metadata Metadata  `json:"metadata"`
}

type Finding struct {
	ID          string      `json:"id"`
	RuleID      string      `json:"rule_id"`
	RuleName    string      `json:"rule_name"`
	Severity    string      `json:"severity"`
	Confidence  string      `json:"confidence"`
	Category    string      `json:"category"`
	Location    Location    `json:"location"`
	Match       Match       `json:"match"`
	Validation  Validation  `json:"validation"`
	Remediation Remediation `json:"remediation"`
	LineHash    string      `json:"-"`
	RawSecret   string      `json:"-"`
}

type Location struct {
	File        string     `json:"file"`
	LineStart   int        `json:"line_start"`
	LineEnd     int        `json:"line_end"`
	ColumnStart int        `json:"column_start"`
	ColumnEnd   int        `json:"column_end"`
	Commit      *string    `json:"commit"`
	Branch      string     `json:"branch"`
	AuthorEmail string     `json:"author_email"`
	CommittedAt *time.Time `json:"committed_at"`
}

type Match struct {
	RawRedacted string  `json:"raw_redacted"`
	Entropy     float64 `json:"entropy"`
	Length      int     `json:"length"`
}

type Validation struct {
	Status      string         `json:"status"`
	ValidatedAt *time.Time     `json:"validated_at"`
	Method      string         `json:"method"`
	Details     map[string]any `json:"details"`
}

type Remediation struct {
	Status       string     `json:"status"`
	ActionsTaken []string   `json:"actions_taken"`
	ResolvedAt   *time.Time `json:"resolved_at"`
	ResolvedBy   *string    `json:"resolved_by"`
}

type Metadata struct {
	Tool         string    `json:"tool"`
	Version      string    `json:"version"`
	ScannedAt    time.Time `json:"scanned_at"`
	ScanTarget   string    `json:"scan_target"`
	ScanMode     string    `json:"scan_mode"`
	FilesScanned int       `json:"files_scanned"`
	DurationMS   int64     `json:"duration_ms"`
	RulesLoaded  int       `json:"rules_loaded"`
	PolicyFile   string    `json:"policy_file"`
}
