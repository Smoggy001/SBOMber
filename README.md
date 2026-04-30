<p align="center">
  <img src="./docs/assets/Banner.png" alt="SBOMber banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/fluxsecurity/SBOMber/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/fluxsecurity/SBOMber/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="Go version" src="https://img.shields.io/badge/Go-1.26-0f766e?style=flat-square&logo=go" />
  <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-111827?style=flat-square" />
  <img alt="Platforms" src="https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-c2410c?style=flat-square" />
  <img alt="Targets" src="https://img.shields.io/badge/Stacks-npm%20%7C%20Python%20%7C%20Maven%20%7C%20Ruby%20%7C%20Go-1d4ed8?style=flat-square" />
</p>

<p align="center">
  <strong>Scan a folder of repositories. Generate SBOMs. Find vulnerabilities. Know what actually matters.</strong>
</p>

SBOMber is an open-source Go CLI that scans directories of locally cloned Git repositories, extracts their dependencies across five ecosystems, generates standards-based SBOM artifacts, and maps known CVEs against the results using Grype.

It is designed for both local developer workflows and automated CI/CD execution. The current milestone covers the full scanning and SBOM generation pipeline. The next milestone adds CVE enrichment with EPSS scores, CISA KEV flags, GitHub Advisory remediation text, and a human-readable HTML report per repository.

## What It Is Built For

- scanning a workspace that contains many Git repositories at once
- detecting repository stacks from manifests and lockfiles across five ecosystems
- extracting direct and transitive dependencies
- generating `CycloneDX` and `SPDX` SBOM output
- mapping dependencies to known CVEs using Grype
- fitting into CI/CD pipelines, scripts, and local security workflows

## Supported Ecosystems

| Ecosystem | Manifest files | Direct deps | Transitive deps |
|-----------|---------------|-------------|-----------------|
| npm | `package.json`, `yarn.lock`, `package-lock.json` | ✓ | ✓ via lock file |
| Python | `requirements.txt`, `requirements-dev.txt` | ✓ | planned Semester 2 |
| Maven | `pom.xml` | ✓ | planned Semester 2 |
| Ruby | `Gemfile.lock` | ✓ | planned Semester 2 |
| Go | `go.mod` | ✓ | ✓ via `// indirect` |

Transitive resolution for Python, Maven, and Ruby requires running the respective package manager. This is a documented Semester 1 limitation and is planned for Semester 2.

## Quick Start

### Prerequisites

- Go `1.26` or newer (required)
- [Grype](https://github.com/anchore/grype) (optional — required only for `--include-vulnerabilities`)

```bash
# Install Grype (macOS/Linux)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### Build and run (macOS / Linux)

```bash
make tidy
make build
./bin/sbomber
```

### Run without building (macOS / Linux)

```bash
# Launch interactive TUI
make run

# Scan a specific folder
make scan SCAN_PATH=/path/to/your/projects

# Scan with a specific export format
make scan SCAN_PATH=/path/to/repo SCAN_ARGS='--format both'

# Scan and include vulnerability results
make scan SCAN_PATH=/path/to/repo SCAN_ARGS='--include-vulnerabilities'
```

### Non-interactive scan (CI/CD)

```bash
./bin/sbomber scan /path/to/workspace
./bin/sbomber scan /path/to/workspace --format both
./bin/sbomber scan /path/to/workspace --format cyclonedx --include-vulnerabilities
```

### Windows (PowerShell)

```powershell
go mod tidy
go run ./cmd/sbomber

# Build and run
go build -o ./bin/sbomber.exe ./cmd/sbomber
./bin/sbomber.exe

# Scan a specific folder
go run ./cmd/sbomber scan C:\path\to\your\projects
```

### Run tests

```bash
make test
```

## Example Output

Launching the interactive TUI:

```
  ____  ____   ___  __  __ ____
 / ___|| __ ) / _ \|  \/  | __ )  ___ _ __
 \___ \|  _ \| | | | |\/| |  _ \ / _ \ '__| 
  ___) | |_) | |_| | |  | | |_) |  __/ |
 |____/|____/ \___/|_|  |_|____/ \___|_|

  v0.1.0

  A lightweight CLI for scanning local repositories and generating SBOMs.

  SELECT AN OPTION

  ▸ ● Scan current folder    Scan repos in the current directory
    ○ Scan custom folder     Choose a folder to scan
    ○ Version                Show SBOMber version
    ○ Help                   Show usage information
    ○ Exit                   Quit SBOMber

  ↑/↓ navigate  enter select  q quit
```

Scanning a mixed workspace:

```
Found 3 repositories under /workspace

- prettier  /workspace/prettier  [npm]
  exported SBOM: /workspace/prettier/sbom-cyclonedx.xml
  packages:  146 direct, 953 transitive (1099 total)
  direct dependencies (package.json): 146 (runtime: 132, development: 14)
  transitive dependencies: 953
  total known dependencies: 1099
  sample packages: acorn, ansi-styles, browserslist, chalk, cliui

- flask-api  /workspace/flask-api  [python]
  exported SBOM: /workspace/flask-api/sbom-cyclonedx.xml
  packages:  4 direct
  direct dependencies (requirements.txt): 4 (runtime: 4)
  sample packages: flask, jinja2, requests, werkzeug

- my-service  /workspace/my-service  [go]
  exported SBOM: /workspace/my-service/sbom-cyclonedx.xml
  packages:  3 direct, 12 transitive (15 total)
  direct dependencies (go.mod): 3 (runtime: 3)
  transitive dependencies: 12
  total known dependencies: 15
  sample packages: github.com/gin-gonic/gin, github.com/spf13/cobra, golang.org/x/crypto

Scan complete: 3 repositories scanned
```

Vulnerability scanning:

```
- npm-basic  /workspace/npm-basic  [npm]
  exported SBOM: /workspace/npm-basic/sbom-cyclonedx.xml
  packages:  1 direct, 953 transitive (954 total)
  ...
  vulnerabilities found: 3
  critical: 0  high: 1  medium: 2  low: 0
  - CVE-2021-23337 [high] package=lodash type=npm
  - CVE-2020-8203  [high] package=lodash type=npm
```

## CI/CD Targets

SBOMber runs cleanly in non-interactive automation environments:

- `GitHub Actions`
- `GitLab CI/CD`
- `Jenkins`
- `Azure DevOps`

Non-interactive scan mode with the `scan` subcommand and flags:

```bash
./bin/sbomber scan /path/to/workspace --format cyclonedx --include-vulnerabilities
```

Exit codes (Sprint 3):

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no findings above threshold |
| `1` | Scan complete, findings found above threshold |
| `2` | Tool or argument error |

## Platform Targets

SBOMber is built as a cross-platform Go CLI:

- `macOS`
- `Linux`
- `Windows`

Planned distribution:

- GitHub Releases binaries
- `go install`
- Homebrew formula

## Current Status

Sprint 2 is complete. The following are implemented and tested:

**Repository scanning**
- interactive TUI with bubbletea (scan menu, format selection, path input)
- non-interactive `scan` subcommand for CI/CD use
- recursive Git repository discovery across nested folder structures
- per-repository output and workspace total summary

**Ecosystem detection and dependency extraction**
- npm: direct dependencies from `package.json`, transitive from `yarn.lock`
- Python: direct dependencies from `requirements.txt` and `requirements-dev.txt`
- Maven: direct dependencies from `pom.xml`
- Ruby: direct dependencies from `Gemfile.lock`
- Go: direct and indirect dependencies from `go.mod`

**SBOM generation**
- CycloneDX 1.5 XML with `purl` identifiers and scan timestamp
- SPDX 2.3 tag-value format with scan timestamp
- both formats written per repository to the repository directory

**Vulnerability scanning**
- Grype subprocess integration via `--include-vulnerabilities`
- CVE ID, severity, package name, and package type per finding

**Quality**
- unit tests for all packages
- golangci-lint clean (errcheck, govet, ineffassign, staticcheck, unused)
- CI on push and pull request

**Sprint 3 (next — Weeks 10–12)**
- EPSS score per CVE (exploit probability)
- CISA Known Exploited Vulnerabilities flag per CVE
- GitHub Advisory remediation text per CVE
- Package health metadata (maintainers, downloads, last published, risk flags)
- `findings.json` machine-readable output per repository
- HTML report with prioritised findings per repository
- `--output`, `--severity-threshold`, `--fail-on-vuln`, `--no-color` CLI flags
- Exit codes 0/1/2 for CI/CD integration
- Integration test suite

**Semester 2**
- Function-level call graph
- Reachability and taint analysis
- VEX document generation
- Dependency confusion detection

## Project Layout

```text
cmd/sbomber/        CLI entrypoint
internal/cli/       interactive TUI and scan flow (cli.go, tui.go)
internal/discovery/ recursive repository scanning
internal/ecosystem/ manifest-based ecosystem detection
internal/deps/      shared dependency data model
internal/npm/       npm and yarn.lock parsing
internal/python/    requirements.txt parsing
internal/maven/     pom.xml parsing
internal/ruby/      Gemfile.lock parsing
internal/golang/    go.mod parsing
internal/sbom/      CycloneDX and SPDX export
internal/vulnerability/ Grype vulnerability scanning
testdata/fixtures/  integration test fixtures for all five ecosystems
docs/assets/        branding and repository visuals
.github/            CI and community health files
```

## Development

```bash
make fmt       # format all Go source
make test      # run unit tests
make vet       # run go vet
make ci        # fmt + vet + test
make build     # compile to ./bin/sbomber
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup and contribution workflow.

## License

Licensed under [Apache-2.0](./LICENSE).
