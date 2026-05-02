package cli

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Xsamsx/SBOMber/internal/deps"
	"github.com/Xsamsx/SBOMber/internal/discovery"
	"github.com/Xsamsx/SBOMber/internal/ecosystem"
	"github.com/Xsamsx/SBOMber/internal/golang"
	"github.com/Xsamsx/SBOMber/internal/maven"
	"github.com/Xsamsx/SBOMber/internal/npm"
	"github.com/Xsamsx/SBOMber/internal/python"
	"github.com/Xsamsx/SBOMber/internal/ruby"
	"github.com/Xsamsx/SBOMber/internal/sbom"
	"github.com/Xsamsx/SBOMber/internal/vulnerability"
)

const version = "0.1.0"

const (
	colorReset = "\033[0m"
	colorCyan  = "\033[36m"
	colorBlue  = "\033[34m"
	colorBold  = "\033[1m"

	formatCycloneDX = "cyclonedx"
	formatSPDX      = "spdx"
	formatBoth      = "both"
)

// Main executes the CLI and returns the exit code.
func Main(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		return runInteractive(stdin, stdout, stderr)
	}

	switch args[0] {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "sbomber %s\n", version)
		return 0
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func runScan(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", formatCycloneDX, "export format: cyclonedx, spdx, or both")
	includeVulnerabilities := fs.Bool("include-vulnerabilities", false, "scan for vulnerabilities using Grype")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	absoluteRoot, err := resolveScanRoot(root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "resolve path: %v\n", err)
		return 1
	}

	selectedFormat, err := normalizeExportFormat(*format)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid format: %v\n", err)
		return 1
	}

	repos, err := discovery.FindGitRepositories(absoluteRoot)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "scan repositories: %v\n", err)
		return 1
	}

	if len(repos) == 0 {
		_, _ = fmt.Fprintf(stdout, "No repositories found under %s\n", absoluteRoot)
		return 0
	}

	plural := "repositories"
	if len(repos) == 1 {
		plural = "repository"
	}

	_, _ = fmt.Fprintf(stdout, "Selected SBOM export format: %s\n", selectedFormat)
	if *includeVulnerabilities {
		if vulnerability.IsGrypeAvailable() {
			_, _ = fmt.Fprintf(stdout, "Vulnerability scanning: enabled (Grype)\n")

		} else {
			_, _ = fmt.Fprintf(stderr, "WARNING: Vulnerability scanning requested but Grype not found in PATH\n")
			_, _ = fmt.Fprintf(stderr, "Install Grype from: https://github.com/anchore/grype\n")
		}
	}
	_, _ = fmt.Fprintf(stdout, "Found %d %s under %s\n", len(repos), plural, absoluteRoot)
	for _, repo := range repos {
		detection, err := ecosystem.Detect(repo.Path)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "detect ecosystem for %s: %v\n", repo.Path, err)
			return 1
		}

		stack := "unknown"
		if len(detection.Names) > 0 {
			names := make([]string, 0, len(detection.Names))
			for _, name := range detection.Names {
				names = append(names, string(name))
			}

			stack = strings.Join(names, ", ")
		}

		_, _ = fmt.Fprintf(stdout, "- %s  %s  [%s]\n", repo.Name, repo.Path, stack)
		printDependencySummary(stdout, stderr, repo.Name, repo.Path, detection, selectedFormat, *includeVulnerabilities)
	}
	_, _ = fmt.Fprintf(stdout, "\nScan complete: %d repositories scanned\n", len(repos))
	return 0
}

func runInteractive(stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if stdin == os.Stdin && stdout == os.Stdout {
		for {
			action, scanPath, scanFormat, includeVulns := runTUI()
			switch action {
			case "scan":
				if scanPath == "" {
					scanPath = "."
				}
				if scanFormat == "" {
					scanFormat = formatCycloneDX
				}
				// Get absolute path for output folder
				absPath, _ := filepath.Abs(scanPath)
				outputFolder := filepath.Join(absPath, sbom.OutputDirName)

				// Show scanning message
				fmt.Print("\033[H\033[2J") // Clear screen
				fmt.Println()
				fmt.Println("  \033[1m\033[36mScanning...\033[0m")
				fmt.Println()
				fmt.Printf("  Path:   %s\n", absPath)
				fmt.Printf("  Format: %s\n", scanFormat)
				if includeVulns {
					fmt.Println("  Vulns:  enabled (Grype)")
				}
				fmt.Println()
				fmt.Println("  \033[90mThis may take a moment...\033[0m")

				var buf bytes.Buffer
				args := []string{"--format", scanFormat}
				if includeVulns {
					args = append(args, "--include-vulnerabilities")
				}
				args = append(args, scanPath)
				runScan(args, &buf, &buf) // Capture both stdout and stderr

				if quit := showResultsScreen(buf.String(), outputFolder); quit {
					fmt.Print("\033[H\033[2J")
					fmt.Fprint(stdout, "Goodbye!\n")
					return 0
				}
			case "version":
				if quit := showResultsScreen(fmt.Sprintf("SBOMber %s", version), ""); quit {
					return 0
				}
			case "help":
				var buf bytes.Buffer
				printUsage(&buf)
				if quit := showResultsScreen(buf.String(), ""); quit {
					return 0
				}
			case "exit", "":
				fmt.Print("\033[H\033[2J")
				fmt.Fprint(stdout, "Goodbye!\n")
				return 0
			}
		}
	}

	printBanner(stdout)
	_, _ = fmt.Fprintf(stdout, "%sA lightweight CLI for scanning local repositories and generating SBOMs.%s\n\n", colorBlue, colorReset)
	_, _ = fmt.Fprint(stdout, "Choose an option:\n")
	_, _ = fmt.Fprint(stdout, "  1. Scan the current folder\n")
	_, _ = fmt.Fprint(stdout, "  2. Scan a custom folder\n")
	_, _ = fmt.Fprint(stdout, "  3. Show version\n")
	_, _ = fmt.Fprint(stdout, "  4. Show help\n\n")
	_, _ = fmt.Fprint(stdout, "Enter choice [1-4]: ")

	reader := bufio.NewReader(stdin)
	choice, err := reader.ReadString('\n')
	if err != nil && len(choice) == 0 {
		_, _ = fmt.Fprintf(stderr, "read choice: %v\n", err)
		return 1
	}

	switch strings.TrimSpace(choice) {
	case "", "1":
		format, exitCode := promptExportFormat(reader, stdout, stderr)
		if exitCode != 0 {
			return exitCode
		}

		includeVulns, exitCode := promptVulnerabilityScan(reader, stdout, stderr)
		if exitCode != 0 {
			return exitCode
		}

		args := []string{"--format", format}
		if includeVulns {
			args = append(args, "--include-vulnerabilities")
		}
		args = append(args, ".")

		return runScan(args, stdout, stderr)
	case "2":
		_, _ = fmt.Fprint(stdout, "Folder to scan: ")
		path, err := reader.ReadString('\n')
		if err != nil && len(path) == 0 {
			_, _ = fmt.Fprintf(stderr, "read path: %v\n", err)
			return 1
		}

		path = strings.TrimSpace(path)
		if path == "" {
			path = "."
		}

		format, exitCode := promptExportFormat(reader, stdout, stderr)
		if exitCode != 0 {
			return exitCode
		}

		includeVulns, exitCode := promptVulnerabilityScan(reader, stdout, stderr)
		if exitCode != 0 {
			return exitCode
		}

		args := []string{"--format", format}
		if includeVulns {
			args = append(args, "--include-vulnerabilities")
		}
		args = append(args, path)

		return runScan(args, stdout, stderr)
	case "3":
		_, _ = fmt.Fprintf(stdout, "sbomber %s\n", version)
		return 0
	case "4":
		printUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "invalid choice %q\n", strings.TrimSpace(choice))
		return 1
	}
}

func printBanner(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s%s", colorBold, colorCyan)
	_, _ = fmt.Fprint(w, `
  ____  ____   ___  __  __ ____             
 / ___|| __ ) / _ \|  \/  | __ )  ___ _ __  
 \___ \|  _ \| | | | |\/| |  _ \ / _ \ '__| 
  ___) | |_) | |_| | |  | | |_) |  __/ |    
 |____/|____/ \___/|_|  |_|____/ \___|_|    
`)
	_, _ = fmt.Fprintf(w, "%s\n", colorReset)
}

func promptExportFormat(reader *bufio.Reader, stdout io.Writer, stderr io.Writer) (string, int) {
	_, _ = fmt.Fprint(stdout, "\nChoose SBOM export format:\n")
	_, _ = fmt.Fprint(stdout, "  1. CycloneDX\n")
	_, _ = fmt.Fprint(stdout, "  2. SPDX\n")
	_, _ = fmt.Fprint(stdout, "  3. Both\n\n")
	_, _ = fmt.Fprint(stdout, "Enter choice [1-3] (default 1): ")

	choice, err := reader.ReadString('\n')
	if err != nil && len(choice) == 0 {
		_, _ = fmt.Fprintf(stderr, "read format choice: %v\n", err)
		return "", 1
	}

	switch strings.TrimSpace(choice) {
	case "", "1":
		return formatCycloneDX, 0
	case "2":
		return formatSPDX, 0
	case "3":
		return formatBoth, 0
	default:
		_, _ = fmt.Fprintf(stderr, "invalid export format choice %q\n", strings.TrimSpace(choice))
		return "", 1
	}
}

func promptVulnerabilityScan(reader *bufio.Reader, stdout io.Writer, stderr io.Writer) (bool, int) {
	_, _ = fmt.Fprint(stdout, "\nInclude vulnerability scanning with Grype? [y/N]: ")

	choice, err := reader.ReadString('\n')
	if err != nil && len(choice) == 0 {
		_, _ = fmt.Fprintf(stderr, "read vulnerability choice: %v\n", err)
		return false, 1
	}

	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "y", "yes":
		return true, 0
	case "", "n", "no":
		return false, 0
	default:
		_, _ = fmt.Fprintf(stderr, "invalid vulnerability choice %q\n", strings.TrimSpace(choice))
		return false, 1
	}
}

func printDependencySummary(stdout io.Writer, stderr io.Writer, repoName, repoPath string, detection ecosystem.Detection, selectedFormat string, includeVulnerabilities bool) {
	summary, err := buildRepoDependencySummary(repoPath, detection)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "read npm dependencies for %s: %v\n", repoPath, err)
		return
	}

	savedPaths, outputDir, err := sbom.SaveSBOM(repoPath, repoName, summary, selectedFormat)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "save SBOM for %s: %v\n", repoPath, err)
	} else {
		_, _ = fmt.Fprintf(stdout, "  output folder: %s\n", outputDir)
		var spdxPath string
		for _, path := range savedPaths {
			_, _ = fmt.Fprintf(stdout, "  exported SBOM: %s\n", filepath.Base(path))
			if strings.HasSuffix(path, "sbom.spdx") {
				spdxPath = path
			}
		}
		if includeVulnerabilities {
			// Run vulnerability scan and generate HTML report
			scanPath := repoPath
			if spdxPath != "" {
				scanPath = "sbom:" + spdxPath
			}
			generateVulnReport(stdout, stderr, scanPath, outputDir, repoName)
		}
	}

	totalDirect := summary.Count()
	totalTransitive := summary.TransitiveCount()

	if totalDirect == 0 && totalTransitive == 0 {
		return
	}

	_, _ = fmt.Fprintf(stdout, "  packages:  %d direct", totalDirect)
	if totalTransitive > 0 {
		_, _ = fmt.Fprintf(stdout, ", %d transitive (%d total)", totalTransitive, summary.TotalCount())
	}
	_, _ = fmt.Fprintln(stdout)

	sourceLabel := "package.json"
	if containsEcosystem(detection.Names, ecosystem.Python) {
		sourceLabel = "requirements.txt"
	}
	if containsEcosystem(detection.Names, ecosystem.NPM) && containsEcosystem(detection.Names, ecosystem.Python) {
		sourceLabel = "package.json + requirements.txt"
	}

	_, _ = fmt.Fprintf(stdout, "  direct dependencies (%s): %d", sourceLabel, summary.Count())

	runtimeCount := summary.CountByScope(deps.ScopeRuntime)
	devCount := summary.CountByScope(deps.ScopeDev)
	peerCount := summary.CountByScope(deps.ScopePeer)
	optionalCount := summary.CountByScope(deps.ScopeOptional)

	scopeParts := make([]string, 0, 4)
	if runtimeCount > 0 {
		scopeParts = append(scopeParts, fmt.Sprintf("runtime: %d", runtimeCount))
	}
	if devCount > 0 {
		scopeParts = append(scopeParts, fmt.Sprintf("development: %d", devCount))
	}
	if peerCount > 0 {
		scopeParts = append(scopeParts, fmt.Sprintf("peer: %d", peerCount))
	}
	if optionalCount > 0 {
		scopeParts = append(scopeParts, fmt.Sprintf("optional: %d", optionalCount))
	}

	if len(scopeParts) > 0 {
		_, _ = fmt.Fprintf(stdout, " (%s)", strings.Join(scopeParts, ", "))
	}
	_, _ = fmt.Fprint(stdout, "\n")

	if summary.TransitiveCount() > 0 {
		_, _ = fmt.Fprintf(stdout, "  transitive dependencies: %d\n", summary.TransitiveCount())
		_, _ = fmt.Fprintf(stdout, "  total known dependencies: %d\n", summary.TotalCount())
	}

	preview := summary.PreviewNames(5)
	if len(preview) == 0 {
		return
	}

	_, _ = fmt.Fprintf(stdout, "  sample packages: %s\n", strings.Join(preview, ", "))
}

func buildRepoDependencySummary(repoPath string, detection ecosystem.Detection) (deps.Summary, error) {
	summary := deps.Summary{
		Direct:     make([]deps.Dependency, 0),
		Transitive: make([]deps.Dependency, 0),
	}

	if containsEcosystem(detection.Names, ecosystem.NPM) {
		npmSummary, err := npm.ParsePackageJSON(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}

		if enriched, err := npm.EnrichFromYarnLock(repoPath, npmSummary); err == nil {
			npmSummary = enriched
		}

		summary.Direct = append(summary.Direct, npmSummary.Direct...)
		summary.Transitive = append(summary.Transitive, npmSummary.Transitive...)
	}

	if containsEcosystem(detection.Names, ecosystem.Python) {
		pythonSummary, err := python.ParseRequirements(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}
		summary.Direct = append(summary.Direct, pythonSummary.Direct...)
		summary.Transitive = append(summary.Transitive, pythonSummary.Transitive...)
	}
	if containsEcosystem(detection.Names, ecosystem.Maven) {
		mavenSummary, err := maven.ParsePOM(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}
		summary.Direct = append(summary.Direct, mavenSummary.Direct...)
	}

	if containsEcosystem(detection.Names, ecosystem.Ruby) {
		rubySummary, err := ruby.ParseGemfileLock(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}
		summary.Direct = append(summary.Direct, rubySummary.Direct...)
	}

	if containsEcosystem(detection.Names, ecosystem.Go) {
		goSummary, err := golang.ParseGoMod(repoPath)
		if err != nil {
			return deps.Summary{}, err
		}
		summary.Direct = append(summary.Direct, goSummary.Direct...)
		summary.Transitive = append(summary.Transitive, goSummary.Transitive...)
	}

	return summary, nil
}

func generateVulnReport(stdout io.Writer, stderr io.Writer, scanPath, outputDir, repoName string) {
	if !vulnerability.IsGrypeAvailable() {
		_, _ = fmt.Fprintf(stderr, "  note: grype not available, skipping vulnerability scan\n")
		return
	}

	ctx := context.Background()
	vulnResults, err := vulnerability.ScanWithGrype(ctx, scanPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "  vulnerability scan failed: %v\n", err)
		return
	}

	// Print summary to terminal
	if vulnResults.TotalCount == 0 {
		_, _ = fmt.Fprintf(stdout, "  vulnerabilities found: 0\n")
	} else {
		_, _ = fmt.Fprintf(stdout, "  vulnerabilities found: %d\n", vulnResults.TotalCount)
		counts := vulnResults.CountBySeverity()
		for severity, count := range counts {
			_, _ = fmt.Fprintf(stdout, "    - %s: %d\n", severity, count)
		}
	}

	// Generate HTML report
	reportPath, err := vulnerability.GenerateHTMLReport(outputDir, repoName, vulnResults)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "  failed to generate HTML report: %v\n", err)
		return
	}
	_, _ = fmt.Fprintf(stdout, "  HTML report: %s\n", filepath.Base(reportPath))
}

func containsEcosystem(names []ecosystem.Name, candidate ecosystem.Name) bool {
	for _, name := range names {
		if name == candidate {
			return true
		}
	}

	return false
}

func resolveScanRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "."
	}

	root = os.ExpandEnv(root)
	if root == "~" || strings.HasPrefix(root, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		if root == "~" {
			root = home
		} else {
			root = filepath.Join(home, strings.TrimPrefix(root, "~/"))
		}
	}

	return filepath.Abs(root)
}

func normalizeExportFormat(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case formatCycloneDX:
		return formatCycloneDX, nil
	case formatSPDX:
		return formatSPDX, nil
	case formatBoth:
		return formatBoth, nil
	default:
		return "", fmt.Errorf("%q (expected cyclonedx, spdx, or both)", value)
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `SBOMber scans workspaces of local Git repositories.

Usage:
  sbomber
  sbomber scan [path] [--format cyclonedx|spdx|both] [--include-vulnerabilities]
  sbomber version

Flags:
  --format cyclonedx|spdx|both          Export format (default: cyclonedx)
  --include-vulnerabilities             Enable vulnerability scanning with Grype

Examples:
  sbomber
  sbomber scan .
  sbomber scan ../workspace --format cyclonedx
  sbomber scan ../workspace --format both
  sbomber scan ../workspace --include-vulnerabilities
`)
}
