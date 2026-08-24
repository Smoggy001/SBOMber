package composer

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParseComposerLock reads composer.lock and returns a normalized dependency summary.
func ParseComposerLock(root string) (deps.Summary, error) {
	path := filepath.Join(root, "composer.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return deps.Summary{}, err
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return deps.Summary{}, err
	}

	sourceFile := "composer.lock"
	sourcePath := path

	summary := deps.Summary{
		Direct:     make([]deps.Dependency, 0),
		Transitive: make([]deps.Dependency, 0),
	}

	for _, pkg := range lock.Packages {
		summary.Direct = append(summary.Direct, deps.Dependency{
			Name:           pkg.Name,
			Version:        pkg.Version,
			Scope:          deps.ScopeRuntime,
			Ecosystem:      "composer",
			IsDirect:       true,
			SourceFile:     sourceFile,
			SourceLocation: sourcePath,
		})
	}

	for _, pkg := range lock.PackagesDev {
		summary.Direct = append(summary.Direct, deps.Dependency{
			Name:           pkg.Name,
			Version:        pkg.Version,
			Scope:          deps.ScopeDev,
			Ecosystem:      "composer",
			IsDirect:       true,
			SourceFile:     sourceFile,
			SourceLocation: sourcePath,
		})
	}

	return summary, nil
}
