package python

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

func TestParseRequirements(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte("requests==2.34.0\nflask>=3.0\n# comment\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "requirements-dev.txt"), []byte("pytest==8.0.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements-dev: %v", err)
	}

	summary, err := ParseRequirements(tmp)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(summary.Direct) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(summary.Direct))
	}

	expected := map[string]deps.Scope{
		"flask":    deps.ScopeRuntime,
		"pytest":   deps.ScopeDev,
		"requests": deps.ScopeRuntime,
	}

	for _, dep := range summary.Direct {
		if expected[dep.Name] != dep.Scope {
			t.Fatalf("expected %s scope %s, got %s", dep.Name, expected[dep.Name], dep.Scope)
		}
	}
}
