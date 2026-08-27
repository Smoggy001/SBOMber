package reachability

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// fileURL builds a correctly percent-encoded file:// URL from an absolute
// filesystem path, cross-platform. This matters concretely here: this
// repo's own path contains a space ("Project Uni"), which a naively
// concatenated file:// string would mangle.
func fileURL(absPath string) string {
	p := filepath.ToSlash(absPath)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// fixtureEnv points GOPROXY and govulncheck's -db at the committed,
// offline testdata/fixtures/reachability fixture (see
// docs/design/reachability.md for how it was built and verified) rather
// than the real https://proxy.golang.org / https://vuln.go.dev, so these
// tests are deterministic and need no network access. t.Setenv restores
// GOPROXY/GOSUMDB after the test and disallows t.Parallel() alongside it,
// which is correct here: these tests shell out to a real subprocess and
// must not race on process-wide environment variables.
func fixtureEnv(t *testing.T) (modulePath, dbURL string) {
	t.Helper()
	if !IsGovulncheckAvailable() {
		t.Skip("govulncheck not installed; install with: go install golang.org/x/vuln/cmd/govulncheck@latest")
	}

	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "reachability"))
	if err != nil {
		t.Fatalf("resolve fixture root: %v", err)
	}
	t.Setenv("GOPROXY", fileURL(filepath.Join(fixtureRoot, "proxy")))
	t.Setenv("GOSUMDB", "off")

	return fixtureRoot, fileURL(filepath.Join(fixtureRoot, "vulndb"))
}

// TestAnalyzeDirectCallIsCritical is the success case: application code
// (main) calls the vulnerable function directly. Verified by hand first —
// see docs/design/reachability.md — before being encoded as this test.
func TestAnalyzeDirectCallIsCritical(t *testing.T) {
	fixtureRoot, dbURL := fixtureEnv(t)
	modulePath := filepath.Join(fixtureRoot, "app", "critical")

	findings, err := analyze(context.Background(), modulePath, dbURL)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.OSV != "GO-9999-0001" {
		t.Fatalf("expected OSV GO-9999-0001, got %q", f.OSV)
	}
	if f.Tier != TierCritical {
		t.Errorf("expected TierCritical, got %q (%s)", f.Tier, f.Explanation)
	}
	if f.Score != 100 {
		t.Errorf("expected score 100, got %d", f.Score)
	}
	if !f.Reachable {
		t.Error("expected Reachable to be true")
	}
}

// TestAnalyzeTransitiveCallIsHigh: main calls a dependency function
// (Wrapper) which itself calls the vulnerable function — the direct
// caller of the vulnerable symbol is dependency code, not app code.
func TestAnalyzeTransitiveCallIsHigh(t *testing.T) {
	fixtureRoot, dbURL := fixtureEnv(t)
	modulePath := filepath.Join(fixtureRoot, "app", "high")

	findings, err := analyze(context.Background(), modulePath, dbURL)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Tier != TierHigh {
		t.Errorf("expected TierHigh, got %q (%s)", f.Tier, f.Explanation)
	}
	if f.Score != 85 {
		t.Errorf("expected score 85, got %d", f.Score)
	}
	if !f.Reachable {
		t.Error("expected Reachable to be true")
	}
	if !strings.Contains(f.DirectCaller, "vendorpkg") {
		t.Errorf("expected DirectCaller to be the vendorpkg dependency, got %q", f.DirectCaller)
	}
}

// TestAnalyzeImportedButUncalledIsLow is the boundary case: the vulnerable
// package is imported and required, but the app never calls the vulnerable
// symbol (it calls an unrelated Safe function instead) — present, but
// unreachable as far as static analysis can tell.
func TestAnalyzeImportedButUncalledIsLow(t *testing.T) {
	fixtureRoot, dbURL := fixtureEnv(t)
	modulePath := filepath.Join(fixtureRoot, "app", "low")

	findings, err := analyze(context.Background(), modulePath, dbURL)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Tier != TierLow {
		t.Errorf("expected TierLow, got %q (%s)", f.Tier, f.Explanation)
	}
	if f.Reachable {
		t.Error("expected Reachable to be false")
	}
}

// TestAnalyzeMissingGovulncheckIsError is the failure/unknown-path case:
// govulncheck not being installed must return a clear error, matching how
// internal/vulnerability.ScanWithGrype fails when Grype is missing.
func TestAnalyzeMissingGovulncheckIsError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := Analyze(context.Background(), ".")
	if err == nil {
		t.Fatal("expected an error when govulncheck is not installed, got nil")
	}
	if !strings.Contains(err.Error(), "govulncheck not found") {
		t.Errorf("expected a clear 'not found' error, got: %v", err)
	}
}
