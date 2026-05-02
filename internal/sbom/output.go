package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	SBOMberDir = ".sbomber"
	ReportsDir = "reports"
)

// GetOutputDir returns the central output directory for a project.
// Output is stored at ~/.sbomber/reports/<sanitized-project-name>/
func GetOutputDir(projectPath string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home directory: %w", err)
	}

	projectName := sanitizeProjectName(projectPath)
	outputDir := filepath.Join(home, SBOMberDir, ReportsDir, projectName)

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}

	return outputDir, nil
}

// GetSBOMberHome returns the SBOMber home directory (~/.sbomber)
func GetSBOMberHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home directory: %w", err)
	}

	sbomberHome := filepath.Join(home, SBOMberDir)
	if err := os.MkdirAll(sbomberHome, 0o755); err != nil {
		return "", fmt.Errorf("create sbomber home: %w", err)
	}

	return sbomberHome, nil
}

// sanitizeProjectName creates a safe directory name from a project path
func sanitizeProjectName(projectPath string) string {
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		absPath = projectPath
	}

	baseName := filepath.Base(absPath)
	if baseName == "." || baseName == "/" {
		baseName = "root"
	}

	safeName := regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(baseName, "_")
	if safeName == "" {
		safeName = "project"
	}

	hash := sha256.Sum256([]byte(absPath))
	shortHash := hex.EncodeToString(hash[:])[:8]

	return fmt.Sprintf("%s_%s", strings.ToLower(safeName), shortHash)
}
