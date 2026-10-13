package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/reachability"
	"github.com/Xsamsx/SBOMber/internal/vulnerability"
)

// lookupExploitIntel is swapped out in tests so they make no network calls.
var lookupExploitIntel = vulnerability.LookupExploitIntel

type reachabilityReport struct {
	Path            string                            `json:"path"`
	OverallPercent  int                               `json:"overallPercent"`
	OverallBand     reachability.RiskBand             `json:"overallBand"`
	CalledFunctions []reachability.CalledFunctionRisk `json:"calledFunctions"`
	NotCalled       []reachability.Finding            `json:"notCalled"`
}

func runReachability(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("reachability", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outputJSON := fs.Bool("json", false, "output results as JSON")
	dbURL := fs.String("db", "", "vulnerability database URL (default: https://vuln.go.dev)")
	noColor := fs.Bool("no-color", false, "disable ANSI color output")

	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if *noColor || *outputJSON {
		setColorOutput(false)
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if !reachability.IsGovulncheckAvailable() {
		_, _ = fmt.Fprintf(stderr, "ERROR: govulncheck is not installed\n")
		_, _ = fmt.Fprintf(stderr, "Install it with: go install golang.org/x/vuln/cmd/govulncheck@latest\n")
		return 2
	}

	ctx := context.Background()
	if !*outputJSON {
		_, _ = fmt.Fprintf(stderr, "Building call graph with govulncheck...\n")
	}
	findings, err := reachability.AnalyzeWithDB(ctx, absRoot, *dbURL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	var cves []string
	var notCalled []reachability.Finding
	for _, f := range findings {
		if f.Reachable {
			cves = append(cves, f.CVEs...)
		} else {
			notCalled = append(notCalled, f)
		}
	}
	sort.Slice(notCalled, func(i, j int) bool { return notCalled[i].OSV < notCalled[j].OSV })

	progress := func(done, total int) {
		if !*outputJSON {
			_, _ = fmt.Fprintf(stderr, "\rLooking up CVSS scores on NVD... %d/%d", done, total)
			if done == total {
				_, _ = fmt.Fprintln(stderr)
			}
		}
	}
	intel := make(map[string]reachability.ExploitIntel)
	for cve, in := range lookupExploitIntel(ctx, cves, progress) {
		intel[cve] = reachability.ExploitIntel{CVSS: in.CVSS, EPSS: in.EPSS, InKEV: in.InCISAKEV}
	}

	called := reachability.ScoreCalledFunctions(findings, intel)
	percent, band := reachability.OverallRisk(called)
	report := reachabilityReport{
		Path:            absRoot,
		OverallPercent:  percent,
		OverallBand:     band,
		CalledFunctions: called,
		NotCalled:       notCalled,
	}
	if report.NotCalled == nil {
		report.NotCalled = []reachability.Finding{}
	}

	if *outputJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		return 0
	}

	printReachabilityReport(stdout, report)
	return 0
}

func bandColor(band reachability.RiskBand) string {
	switch band {
	case reachability.BandHigh:
		return colorRed
	case reachability.BandMedium:
		return colorYellow
	case reachability.BandLow:
		return colorCyan
	default:
		return colorGreen
	}
}

func printReachabilityReport(w io.Writer, r reachabilityReport) {
	_, _ = fmt.Fprintf(w, "\n%sReachability Risk%s  %s\n", colorBold, colorReset, r.Path)
	_, _ = fmt.Fprintf(w, "%sScored only against vulnerable functions the call graph shows your code calls.%s\n\n", colorDim, colorReset)

	_, _ = fmt.Fprintf(w, "  Overall risk: %s%s%d%% %s%s\n", colorBold, bandColor(r.OverallBand), r.OverallPercent, r.OverallBand, colorReset)
	_, _ = fmt.Fprintf(w, "  %d vulnerable function(s) called, %d vulnerable package(s) present but never called (not scored)\n\n",
		len(r.CalledFunctions), len(r.NotCalled))

	for i, c := range r.CalledFunctions {
		color := bandColor(c.Band)
		_, _ = fmt.Fprintf(w, "  %s%2d. %3d%% %-11s%s  %s  %s\n", color, i+1, c.Percent, c.Band, colorReset, c.OSV, c.Symbol)
		if c.Summary != "" {
			_, _ = fmt.Fprintf(w, "      %s\n", c.Summary)
		}

		cveText := "no CVE"
		if len(c.CVEs) > 0 {
			cveText = strings.Join(c.CVEs, ", ")
		}
		cvssText := fmt.Sprintf("CVSS %.1f", c.CVSS)
		if c.SeverityAssumed {
			cvssText = "CVSS n/a (assumed 5.0)"
		}
		kevText := "not in CISA KEV"
		if c.InKEV {
			kevText = "IN CISA KEV"
		}
		_, _ = fmt.Fprintf(w, "      %s · %s · EPSS %.2f%% · %s\n", cveText, cvssText, c.EPSS*100, kevText)

		_, _ = fmt.Fprintf(w, "      Call path:\n")
		for j, frame := range c.CallPath {
			marker := "  "
			if j > 0 {
				marker = "→ "
			}
			who := "dependency"
			switch {
			case frame.InApp:
				who = "your code"
			case j == len(c.CallPath)-1:
				who = "VULNERABLE"
			case frame.Module == "stdlib":
				who = "stdlib"
			}
			loc := frame.Location()
			if loc != "" {
				loc = "  " + colorDim + loc + colorReset
			}
			_, _ = fmt.Fprintf(w, "        %s%-10s %s%s\n", marker, who, frame.Name(), loc)
		}

		b := c.Breakdown
		_, _ = fmt.Fprintf(w, "      Score: severity %.1f + exploit %.1f + KEV %.0f + call %.0f = %d%%\n",
			b.Severity, b.ExploitChance, b.KnownExploited, b.CallProximity, c.Percent)
		if c.FixedVersion != "" {
			_, _ = fmt.Fprintf(w, "      Fix: upgrade to %s\n", c.FixedVersion)
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(r.NotCalled) > 0 {
		ids := make([]string, 0, len(r.NotCalled))
		for _, f := range r.NotCalled {
			ids = append(ids, f.OSV)
		}
		_, _ = fmt.Fprintf(w, "  %sPresent but never called (not scored): %s%s\n\n", colorDim, strings.Join(ids, ", "), colorReset)
	}

	_, _ = fmt.Fprintf(w, "  %sScoring chart (max 100%%)%s\n", colorBold, colorReset)
	_, _ = fmt.Fprintf(w, "    Severity         CVSS / 10 × %.0f                       up to %.0f\n", reachability.MaxSeverityPoints, reachability.MaxSeverityPoints)
	_, _ = fmt.Fprintf(w, "    Exploit chance   EPSS × %.0f                            up to %.0f\n", reachability.MaxExploitPoints, reachability.MaxExploitPoints)
	_, _ = fmt.Fprintf(w, "    Known exploited  in CISA KEV                          +%.0f\n", reachability.KnownExploitedPoints)
	_, _ = fmt.Fprintf(w, "    Call proximity   your code calls it +%.0f, via a dependency +%.0f\n", reachability.DirectCallPoints, reachability.IndirectCallPoints)
	_, _ = fmt.Fprintf(w, "    %s0-20%% Secure%s · %s21-39%% Low%s · %s40-69%% Medium%s · %s70-100%% High%s\n",
		colorGreen, colorReset, colorCyan, colorReset, colorYellow, colorReset, colorRed, colorReset)
}
