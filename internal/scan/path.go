package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolveRulesDir(defaultDir string) (string, error) {
	if defaultDir == "" {
		defaultDir = "rules"
	}

	if info, err := os.Stat(defaultDir); err == nil && info.IsDir() && hasYAML(defaultDir) {
		return defaultDir, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := cwd
	for {
		candidate := filepath.Join(dir, defaultDir)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() && hasYAML(candidate) {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("default rules directory not found: %s", defaultDir)
}

func hasYAML(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			return true
		}
	}
	return false
}
