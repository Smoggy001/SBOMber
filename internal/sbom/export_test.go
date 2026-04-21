package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

func TestSaveSBOMCreatesFiles(t *testing.T) {
	tmp := t.TempDir()
	summary := deps.Summary{
		Direct: []deps.Dependency{
			{Name: "react", Version: "19.1.0", Scope: deps.ScopeRuntime},
			{Name: "vitest", Version: "1.6.1", Scope: deps.ScopeDev},
		},
		Transitive: []deps.Dependency{
			{Name: "vite", Version: "5.4.0", Scope: deps.ScopeRuntime},
		},
	}

	files, err := SaveSBOM(tmp, "prettier", summary, "both")
	if err != nil {
		t.Fatalf("expected no error saving sbom, got %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files saved, got %d", len(files))
	}

	for _, path := range files {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected file %q to exist, got error %v", path, err)
		}
	}

	cyclonePath := filepath.Join(tmp, cycloneDXFilename)
	if _, err := os.ReadFile(cyclonePath); err != nil {
		t.Fatalf("expected cyclonedx file to be readable, got %v", err)
	}

	spdxPath := filepath.Join(tmp, spdxFilename)
	if _, err := os.ReadFile(spdxPath); err != nil {
		t.Fatalf("expected spdx file to be readable, got %v", err)
	}
}
