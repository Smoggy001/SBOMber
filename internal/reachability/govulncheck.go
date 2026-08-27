// Package reachability determines whether a known vulnerability in a Go
// module is actually reachable from application code, not just imported.
//
// It does this by shelling out to govulncheck (golang.org/x/vuln/cmd/govulncheck,
// the Go team's own static reachability analyzer), the same way
// internal/vulnerability shells out to Grype — govulncheck's -json output is
// its documented, stable integration contract; the package internals it's
// built from (SSA construction, call-graph analysis) are not part of Go's
// public API surface, so wrapping the CLI is the sanctioned approach rather
// than a shortcut. See docs/design/reachability.md for how the confidence
// tiers below were derived and verified against real govulncheck output.
package reachability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Tier is a confidence classification for whether a vulnerability is
// actually reachable, matching the four-tier model in
// docs/design/reachability.md.
type Tier string

const (
	// TierCritical: application code directly calls the vulnerable
	// function. govulncheck found a call trace whose first frame after
	// the vulnerable function itself belongs to the module being scanned.
	TierCritical Tier = "CRITICAL"
	// TierHigh: the vulnerable function is reachable, but only through a
	// dependency that calls it on the application's behalf — the direct
	// caller is not in the module being scanned.
	TierHigh Tier = "HIGH"
	// TierMedium: govulncheck could not perform full symbol-level
	// call-graph analysis for this module (it fell back to a coarser
	// scan level), so reachability could not be confirmed either way.
	TierMedium Tier = "MEDIUM"
	// TierLow: the vulnerable package is imported/required, but no call
	// path to the vulnerable symbol was found — present, but (as far as
	// static analysis can tell) never invoked.
	TierLow Tier = "LOW"
)

// Finding is a per-vulnerability reachability verdict.
type Finding struct {
	OSV          string `json:"osv"`
	Summary      string `json:"summary"`
	FixedVersion string `json:"fixedVersion,omitempty"`
	Tier         Tier   `json:"tier"`
	Score        int    `json:"score"`
	Reachable    bool   `json:"reachable"`
	// DirectCaller is the package that directly calls the vulnerable
	// symbol, when a function-level trace was found.
	DirectCaller string `json:"directCaller,omitempty"`
	Explanation  string `json:"explanation"`
}

// IsGovulncheckAvailable reports whether govulncheck is installed and on
// PATH.
func IsGovulncheckAvailable() bool {
	_, err := exec.LookPath("govulncheck")
	return err == nil
}

// Analyze runs govulncheck against the Go module rooted at modulePath and
// returns a reachability Finding for every vulnerability it reports,
// classified into the four confidence tiers. It uses govulncheck's default
// vulnerability database (https://vuln.go.dev) and whatever GOPROXY the
// caller's environment already has configured.
func Analyze(ctx context.Context, modulePath string) ([]Finding, error) {
	return analyze(ctx, modulePath, "")
}

// analyze is Analyze's implementation, with an optional dbURL override
// ("" for govulncheck's default). Exposed unexported so tests can point it
// at a local, offline test vulnerability database (see
// docs/design/reachability.md) without changing Analyze's public
// signature — production use always takes the default database.
func analyze(ctx context.Context, modulePath, dbURL string) ([]Finding, error) {
	if !IsGovulncheckAvailable() {
		return nil, fmt.Errorf("govulncheck not found in PATH - install: go install golang.org/x/vuln/cmd/govulncheck@latest")
	}

	args := []string{"-json"}
	if dbURL != "" {
		args = append(args, "-db", dbURL)
	}
	args = append(args, "./...")

	cmd := exec.CommandContext(ctx, "govulncheck", args...)
	cmd.Dir = modulePath
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		// govulncheck exits non-zero when it finds reachable
		// vulnerabilities; that is expected output, not a failure.
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("run govulncheck: %w", err)
		}
	}

	rootModule, symbolLevel, osvSummaries, findingsByOSV, err := parseGovulncheckOutput(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse govulncheck output: %w", err)
	}

	results := make([]Finding, 0, len(findingsByOSV))
	for osvID, findings := range findingsByOSV {
		results = append(results, classify(osvID, osvSummaries[osvID], findings, rootModule, symbolLevel))
	}
	return results, nil
}

func classify(osvID string, summary govulncheckOSV, findings []govulncheckFinding, rootModule string, symbolLevel bool) Finding {
	base := Finding{
		OSV:     osvID,
		Summary: summary.Summary,
	}
	if len(findings) > 0 {
		base.FixedVersion = findings[0].FixedVersion
	}

	if !symbolLevel {
		base.Tier = TierMedium
		base.Score = 50
		base.Explanation = "govulncheck could not perform full symbol-level call-graph analysis for this module (it fell back to a coarser scan level), so reachability could not be confirmed either way"
		return base
	}

	// Find the most complete (deepest) function-level trace for this
	// OSV, if any. A trace with a function name on its first frame is
	// one where govulncheck actually resolved a call path, not just
	// "this package is present."
	var best *govulncheckFinding
	for i := range findings {
		f := &findings[i]
		if len(f.Trace) == 0 || f.Trace[0].Function == "" {
			continue
		}
		if best == nil || len(f.Trace) > len(best.Trace) {
			best = f
		}
	}

	if best == nil {
		base.Tier = TierLow
		base.Score = 5
		base.Reachable = false
		base.Explanation = "imported/required, but no call path to the vulnerable symbol was found"
		return base
	}

	base.Reachable = true
	// trace[0] is the vulnerable function itself; trace[1], if present,
	// is its direct caller.
	if len(best.Trace) > 1 {
		base.DirectCaller = best.Trace[1].Package
		if best.Trace[1].Module == rootModule {
			base.Tier = TierCritical
			base.Score = 100
			base.Explanation = "application code directly calls the vulnerable function"
			return base
		}
	}

	base.Tier = TierHigh
	base.Score = 85
	base.Explanation = "the vulnerable function is reachable, but is called by a dependency on the application's behalf, not directly by application code"
	return base
}

// govulncheck -json emits a stream of top-level JSON objects (not a single
// array): {"config":...}, {"SBOM":...}, {"progress":...}, {"osv":...}, and
// {"finding":...}, in that rough order. See docs/design/reachability.md for
// how this shape was determined by direct inspection of real output.
type govulncheckEnvelope struct {
	Config  *govulncheckConfig  `json:"config"`
	SBOM    *govulncheckSBOM    `json:"SBOM"`
	OSV     *govulncheckOSV     `json:"osv"`
	Finding *govulncheckFinding `json:"finding"`
}

type govulncheckConfig struct {
	ScanLevel string `json:"scan_level"`
}

type govulncheckSBOM struct {
	Roots []string `json:"roots"`
}

type govulncheckOSV struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type govulncheckFinding struct {
	OSV          string                  `json:"osv"`
	FixedVersion string                  `json:"fixed_version"`
	Trace        []govulncheckTraceFrame `json:"trace"`
}

type govulncheckTraceFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Version  string `json:"version"`
}

func parseGovulncheckOutput(output []byte) (rootModule string, symbolLevel bool, osvSummaries map[string]govulncheckOSV, findingsByOSV map[string][]govulncheckFinding, err error) {
	symbolLevel = true
	osvSummaries = make(map[string]govulncheckOSV)
	findingsByOSV = make(map[string][]govulncheckFinding)

	dec := json.NewDecoder(bytes.NewReader(output))
	for dec.More() {
		var env govulncheckEnvelope
		if decErr := dec.Decode(&env); decErr != nil {
			return "", false, nil, nil, fmt.Errorf("decode govulncheck JSON stream: %w", decErr)
		}
		switch {
		case env.Config != nil:
			symbolLevel = env.Config.ScanLevel == "symbol"
		case env.SBOM != nil && len(env.SBOM.Roots) > 0:
			rootModule = env.SBOM.Roots[0]
		case env.OSV != nil:
			osvSummaries[env.OSV.ID] = *env.OSV
		case env.Finding != nil:
			findingsByOSV[env.Finding.OSV] = append(findingsByOSV[env.Finding.OSV], *env.Finding)
		}
	}

	if rootModule == "" {
		return "", false, nil, nil, fmt.Errorf("govulncheck output did not include an SBOM root module")
	}
	return rootModule, symbolLevel, osvSummaries, findingsByOSV, nil
}
