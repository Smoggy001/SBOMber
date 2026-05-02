<p align="center">
  <img src="./docs/assets/Banner.png" alt="SBOMber banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/fluxsecurity/SBOMber/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/fluxsecurity/SBOMber/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="Go version" src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go" />
  <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square" />
</p>

<p align="center">
  <strong>Scan repositories. Generate SBOMs. Find vulnerabilities.</strong>
</p>

---

SBOMber is an open-source CLI that scans local Git repositories, extracts dependencies, generates SBOM artifacts (CycloneDX/SPDX), and finds CVEs using Grype.

## Quick Start

```bash
# Build
make build

# Run interactive TUI
./bin/sbomber

# Or scan directly
./bin/sbomber scan /path/to/repos --format cyclonedx --include-vulnerabilities
```

**Requirements:** Go 1.26+ and [Grype](https://github.com/anchore/grype) (for vulnerability scanning)

## Features

| Feature | Status |
|---------|--------|
| Interactive TUI | done |
| npm/yarn dependencies | done |
| Python requirements.txt | done |
| Maven pom.xml | done |
| Ruby Gemfile.lock | done |
| Go go.mod | done |
| CycloneDX export | done |
| SPDX export | done |
| Grype vulnerability scan | done |
| HTML vulnerability report | planned |

## Usage

### Interactive Mode

```bash
./bin/sbomber
```

Navigate with arrow keys, select with Enter. After scan completes, press Enter to return to menu.

### CLI Mode (CI/CD)

```bash
# Scan current directory
./bin/sbomber scan .

# Scan with specific format
./bin/sbomber scan /path/to/repos --format both

# Include vulnerability scanning
./bin/sbomber scan /path/to/repos --include-vulnerabilities
```

### Output

SBOMs are saved in the scanned repository:
- `sbom-cyclonedx.xml` - CycloneDX 1.5 format
- `sbom.spdx` - SPDX 2.3 format

## Development

```bash
make fmt      # format code
make test     # run tests
make vet      # run go vet
make build    # build binary
```

## License

[Apache-2.0](./LICENSE)
