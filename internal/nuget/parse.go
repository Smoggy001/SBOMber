package nuget

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/deps"
)

type nugetLock struct {
	Version      int                                   `json:"version"`
	Dependencies map[string]map[string]nugetDependency `json:"dependencies"`
}

type nugetDependency struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

// ParsePackagesLock reads packages.lock.json and returns a normalized dependency summary.
func ParsePackagesLock(root string) (deps.Summary, error) {
	path := filepath.Join(root, "packages.lock.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return deps.Summary{}, err
	}

	var lock nugetLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return deps.Summary{}, err
	}

	sourceFile := "packages.lock.json"
	sourcePath := path

	summary := deps.Summary{
		Direct:     make([]deps.Dependency, 0),
		Transitive: make([]deps.Dependency, 0),
	}

	seen := make(map[string]bool)

	for _, frameworkDeps := range lock.Dependencies {
		for name, dep := range frameworkDeps {
			key := strings.ToLower(name)
			if seen[key] {
				continue
			}
			seen[key] = true

			isDirect := strings.EqualFold(dep.Type, "Direct")
			depth := 1
			if isDirect {
				depth = 0
			}

			d := deps.Dependency{
				Name:           name,
				Version:        dep.Resolved,
				Scope:          deps.ScopeRuntime,
				Ecosystem:      "nuget",
				IsDirect:       isDirect,
				Depth:          depth,
				SourceFile:     sourceFile,
				SourceLocation: sourcePath,
			}

			if isDirect {
				summary.Direct = append(summary.Direct, d)
			} else {
				summary.Transitive = append(summary.Transitive, d)
			}
		}
	}

	return summary, nil
}
