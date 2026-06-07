# SBOMber Development Status

Last updated: 2026-05-02

## Current State

Sprint 2 complete. All core features implemented:

- Interactive TUI with loop mode (scan → results → back to menu)
- Multi-repo Git scanning (recursive discovery)
- Ecosystem detection + dependency extraction:
  - npm (package.json + yarn.lock/package-lock.json)
  - Python (requirements.txt)
  - Maven (pom.xml)
  - Ruby (Gemfile.lock)
  - Go (go.mod)
- SBOM export:
  - CycloneDX 1.5 XML
  - SPDX 2.3 tag-value
- Grype vulnerability scanning (--include-vulnerabilities)
- CI/CD non-interactive mode

## Output Locations

SBOMs are written to each scanned repository:
- `{repo}/sbom-cyclonedx.xml`
- `{repo}/sbom.spdx`

## Next Up (Sprint 3)

- HTML vulnerability report per repository
- EPSS scores per CVE
- CISA KEV flags
- GitHub Advisory remediation text
- `--output` flag for custom output directory
- `--severity-threshold` and `--fail-on-vuln` for CI gates
