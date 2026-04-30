#!/usr/bin/env bash
# SBOMber Sprint 2 — Full Test Suite
# Run from repo root: bash scripts/test_sprint2.sh

set -uo pipefail

SBOMBER="./bin/sbomber"
FIXTURES="testdata/fixtures"
PASS=0
FAIL=0
WARN=0

# ── colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;91m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── helpers ───────────────────────────────────────────────────────────────────
pass() { echo -e "  ${GREEN}✓${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC}  $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; ((WARN++)); }
info() { echo -e "  ${DIM}·${NC}  $1"; }
header() {
  echo ""
  echo -e "${BOLD}${BLUE}── $1 ──────────────────────────────────────────────────${NC}"
}

check() {
  local label="$1"
  local condition="$2"
  if eval "$condition" &>/dev/null; then
    pass "$label"
  else
    fail "$label"
  fi
}

# ── preflight ─────────────────────────────────────────────────────────────────
header "Preflight"

if [[ ! -f "$SBOMBER" ]]; then
  echo -e "${RED}Binary not found. Run 'make build' first.${NC}"
  exit 1
fi
pass "Binary exists: ./bin/sbomber"

make build &>/dev/null && pass "make build — compiles without errors" \
                       || { fail "make build — compilation failed"; exit 1; }

# clean leftover SBOM files from previous runs
find "$FIXTURES" -name "sbom-cyclonedx.xml" -delete 2>/dev/null || true
find "$FIXTURES" -name "sbom.spdx"          -delete 2>/dev/null || true
pass "Cleaned leftover SBOM files from fixtures"

# ── TC-20: unit tests ─────────────────────────────────────────────────────────
header "TC-20  Unit tests"
if make test &>/dev/null; then
  pass "TC-20  All unit tests pass (make test)"
else
  fail "TC-20  Unit tests failed — run 'make test' to see which package"
fi

# ── TC-21: linter ─────────────────────────────────────────────────────────────
header "TC-21  Code quality"
LINT_OUT=$(golangci-lint run ./... 2>&1); LINT_EXIT=$?
if [[ -z "$LINT_OUT" ]]; then
  pass "TC-21  golangci-lint — 0 issues"
else
  ISSUE_COUNT=$(echo "$LINT_OUT" | grep -c "^\s" || true)
  fail "TC-21  golangci-lint — $ISSUE_COUNT issue(s) found"
  echo "$LINT_OUT" | head -6 | while read -r line; do info "$line"; done
fi

# ── TC-01: single repo ────────────────────────────────────────────────────────
header "TC-01  Single repository discovery"
OUT=$("$SBOMBER" scan "$FIXTURES/npm-basic" 2>&1)
check "TC-01  Found exactly 1 repository" \
  "echo '$OUT' | grep -q 'Found 1 repository'"
check "TC-01  Repository name shown in output" \
  "echo '$OUT' | grep -q 'npm-basic'"
check "TC-01  Workspace total line present" \
  "echo '$OUT' | grep -q 'Scan complete'"

# ── TC-02: multi-repo workspace ───────────────────────────────────────────────
header "TC-02  Multi-repository workspace discovery"
OUT=$("$SBOMBER" scan "$FIXTURES/multi-repo-workspace" 2>&1)
check "TC-02  Found exactly 2 repositories" \
  "echo '$OUT' | grep -q 'Found 2 repositories'"
check "TC-02  npm-basic repo block present" \
  "echo '$OUT' | grep -q 'npm-basic'"
check "TC-02  npm-clean repo block present" \
  "echo '$OUT' | grep -q 'npm-clean'"
check "TC-02  Workspace total shows 2 repositories scanned" \
  "echo '$OUT' | grep -q '2 repositories scanned'"

# ── TC-03: no-manifests ───────────────────────────────────────────────────────
header "TC-03  No supported manifests — graceful handling"
OUT=$("$SBOMBER" scan "$FIXTURES/no-manifests" 2>&1)
EXIT=$?
if [[ $EXIT -eq 0 ]]; then
  pass "TC-03  Tool exits cleanly with code 0 on unknown ecosystem"
else
  fail "TC-03  Tool exited with non-zero code $EXIT on unknown ecosystem"
fi
if echo "$OUT" | grep -q "unknown\|no repositories\|No repositories"; then
  pass "TC-03  Output indicates no supported ecosystem detected"
else
  warn "TC-03  Output does not clearly indicate unknown/unsupported ecosystem"
fi

# ── TC-04–08: ecosystem detection ─────────────────────────────────────────────
header "TC-04–08  Ecosystem detection — all five stacks"

declare -A ECOSYSTEMS=(
  ["TC-04  npm detected from package.json"]="$FIXTURES/npm-basic [npm]"
  ["TC-05  Python detected from requirements.txt"]="$FIXTURES/python-basic [python]"
  ["TC-06  Maven detected from pom.xml"]="$FIXTURES/maven-basic [maven]"
  ["TC-07  Ruby detected from Gemfile.lock"]="$FIXTURES/ruby-basic [ruby]"
  ["TC-08  Go detected from go.mod"]="$FIXTURES/go-basic [go]"
)

for label in "${!ECOSYSTEMS[@]}"; do
  spec="${ECOSYSTEMS[$label]}"
  fixture=$(echo "$spec" | awk '{print $1}')
  tag=$(echo "$spec"     | awk '{print $2}')
  OUT=$("$SBOMBER" scan "$fixture" 2>&1)
  if echo "$OUT" | grep -q "$tag"; then
    pass "$label"
  else
    fail "$label"
  fi
done

# ── TC-09: npm transitive ─────────────────────────────────────────────────────
header "TC-09  npm direct + transitive dependency extraction"
OUT=$("$SBOMBER" scan "$FIXTURES/npm-basic" 2>&1)
check "TC-09  lodash appears in sample packages" \
  "echo '$OUT' | grep -q 'lodash'"
check "TC-09  Direct dependency count shown" \
  "echo '$OUT' | grep -q 'direct'"
if echo "$OUT" | grep -q "transitive"; then
  pass "TC-09  Transitive dependencies detected (lock file parsed)"
else
  warn "TC-09  No transitive deps shown — fixture may be missing yarn.lock"
fi

# ── TC-10: no lock file ───────────────────────────────────────────────────────
header "TC-10  npm with no lock file — fallback to package.json only"
OUT=$("$SBOMBER" scan "$FIXTURES/npm-no-lockfile" 2>&1)
EXIT=$?
check "TC-10  Tool exits with code 0 (no crash)" "[[ $EXIT -eq 0 ]]"
check "TC-10  At least 1 direct dependency found from package.json" \
  "echo '$OUT' | grep -q '1 direct'"
check "TC-10  No error messages in output" \
  "! echo '$OUT' | grep -qi 'error\|panic\|fatal'"

# ── TC-11: Python ─────────────────────────────────────────────────────────────
header "TC-11  Python direct dependency extraction from requirements.txt"
OUT=$("$SBOMBER" scan "$FIXTURES/python-basic" 2>&1)
check "TC-11  Exactly 3 direct dependencies found" \
  "echo '$OUT' | grep -q '3 direct'"
check "TC-11  flask found in sample packages" \
  "echo '$OUT' | grep -q 'flask'"
check "TC-11  requests found in sample packages" \
  "echo '$OUT' | grep -q 'requests'"
check "TC-11  jinja2 found in sample packages" \
  "echo '$OUT' | grep -q 'jinja2'"

# ── TC-12: Maven ──────────────────────────────────────────────────────────────
header "TC-12  Maven direct dependency extraction from pom.xml"
OUT=$("$SBOMBER" scan "$FIXTURES/maven-basic" 2>&1)
check "TC-12  Exactly 2 direct dependencies found" \
  "echo '$OUT' | grep -q '2 direct'"
check "TC-12  commons-lang found" \
  "echo '$OUT' | grep -q 'commons-lang'"
check "TC-12  spring-core found" \
  "echo '$OUT' | grep -q 'spring-core'"

# ── TC-13: Ruby ───────────────────────────────────────────────────────────────
header "TC-13  Ruby direct dependency extraction from Gemfile.lock"
OUT=$("$SBOMBER" scan "$FIXTURES/ruby-basic" 2>&1)
check "TC-13  Exactly 2 gems found" \
  "echo '$OUT' | grep -q '2 direct'"
check "TC-13  rack found" \
  "echo '$OUT' | grep -q 'rack'"
check "TC-13  rake found" \
  "echo '$OUT' | grep -q 'rake'"

# ── TC-14: Go ─────────────────────────────────────────────────────────────────
header "TC-14  Go direct + indirect dependency extraction from go.mod"
OUT=$("$SBOMBER" scan "$FIXTURES/go-basic" 2>&1)
check "TC-14  1 direct + 1 transitive (2 total)" \
  "echo '$OUT' | grep -q '1 direct, 1 transitive'"
check "TC-14  gin appears in sample packages" \
  "echo '$OUT' | grep -q 'gin'"
check "TC-14  Transitive count shown" \
  "echo '$OUT' | grep -q 'transitive dependencies: 1'"

# ── TC-15: CycloneDX SBOM ─────────────────────────────────────────────────────
header "TC-15  CycloneDX SBOM — structure and content"
"$SBOMBER" scan "$FIXTURES/npm-basic" &>/dev/null
SBOM="$FIXTURES/npm-basic/sbom-cyclonedx.xml"
check "TC-15  sbom-cyclonedx.xml file written to disk" \
  "[[ -f '$SBOM' ]]"
check "TC-15  CycloneDX 1.5 schema namespace present" \
  "grep -q 'cyclonedx.org/schema/bom/1.5' '$SBOM'"
check "TC-15  metadata timestamp element present" \
  "grep -q '<timestamp>' '$SBOM'"
check "TC-15  Timestamp is not the old hardcoded date 2026-01-01" \
  "! grep -q '2026-01-01' '$SBOM'"
check "TC-15  At least one purl element present" \
  "grep -q '<purl>' '$SBOM'"
check "TC-15  purl type is npm not a wrong ecosystem" \
  "grep -q 'pkg:npm/' '$SBOM'"

# ── TC-16: SPDX ───────────────────────────────────────────────────────────────
header "TC-16  SPDX SBOM — structure and content"
"$SBOMBER" scan --format spdx "$FIXTURES/npm-basic" &>/dev/null
SPDX="$FIXTURES/npm-basic/sbom.spdx"
check "TC-16  sbom.spdx file written to disk" \
  "[[ -f '$SPDX' ]]"
check "TC-16  SPDXVersion: SPDX-2.3 on first line" \
  "head -1 '$SPDX' | grep -q 'SPDX-2.3'"
check "TC-16  Created field present" \
  "grep -q '^Created:' '$SPDX'"
check "TC-16  Timestamp is not the old hardcoded date 2026-01-01" \
  "! grep -q '2026-01-01' '$SPDX'"
check "TC-16  At least one PackageName entry present" \
  "grep -q '^PackageName:' '$SPDX'"

# ── TC-17: both formats ───────────────────────────────────────────────────────
header "TC-17  Both CycloneDX and SPDX generated in one scan"
"$SBOMBER" scan --format both "$FIXTURES/npm-basic" &>/dev/null
check "TC-17  sbom-cyclonedx.xml exists after --format both" \
  "[[ -f '$FIXTURES/npm-basic/sbom-cyclonedx.xml' ]]"
check "TC-17  sbom.spdx exists after --format both" \
  "[[ -f '$FIXTURES/npm-basic/sbom.spdx' ]]"

# ── TC-18: vulnerability scanning ────────────────────────────────────────────
header "TC-18  Vulnerability scanning — known CVEs in lodash 4.17.15"
if ! command -v grype &>/dev/null; then
  warn "TC-18  Grype not found in PATH — skipping vulnerability tests"
else
  OUT=$("$SBOMBER" scan --include-vulnerabilities "$FIXTURES/npm-basic" 2>&1)
  check "TC-18  Vulnerabilities found line present in output" \
    "echo '$OUT' | grep -q 'vulnerabilities found'"
  if echo "$OUT" | grep -q "vulnerabilities found: 0"; then
    fail "TC-18  0 vulnerabilities found — lodash 4.17.15 should have CVEs"
  else
    pass "TC-18  Non-zero vulnerabilities detected in lodash 4.17.15"
  fi
  check "TC-18  High severity findings reported" \
    "echo '$OUT' | grep -q 'high'"
fi

# ── TC-19: clean project ──────────────────────────────────────────────────────
header "TC-19  Clean project — no CVEs, exit code 0"
if ! command -v grype &>/dev/null; then
  warn "TC-19  Grype not found — skipping clean project test"
else
  "$SBOMBER" scan --include-vulnerabilities "$FIXTURES/npm-clean" &>/dev/null
  EXIT=$?
  check "TC-19  Exit code is 0 for clean project" "[[ $EXIT -eq 0 ]]"
fi

# ── TC-22: CI badge check ─────────────────────────────────────────────────────
header "TC-22  CI pipeline — GitHub Actions"
if command -v curl &>/dev/null; then
  STATUS=$(curl -s "https://github.com/fluxsecurity/SBOMber/actions/workflows/ci.yml/badge.svg" 2>/dev/null || echo "")
  if echo "$STATUS" | grep -q "passing"; then
    pass "TC-22  GitHub Actions CI badge shows passing"
  elif echo "$STATUS" | grep -q "failing"; then
    fail "TC-22  GitHub Actions CI badge shows failing"
  else
    warn "TC-22  Could not read CI badge — check manually at github.com/fluxsecurity/SBOMber/actions"
  fi
else
  warn "TC-22  curl not available — check CI manually"
fi

# ── cleanup ───────────────────────────────────────────────────────────────────
find "$FIXTURES" -name "sbom-cyclonedx.xml" -delete 2>/dev/null || true
find "$FIXTURES" -name "sbom.spdx"          -delete 2>/dev/null || true

# ── summary ───────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + WARN))
echo ""
echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
echo -e "${BOLD}  Sprint 2 Test Results${NC}"
echo -e "────────────────────────────────────────────────────────"
echo -e "  ${GREEN}Passed:${NC}   $PASS"
echo -e "  ${RED}Failed:${NC}   $FAIL"
echo -e "  ${YELLOW}Warnings:${NC} $WARN"
echo -e "  Total:    $TOTAL"
echo -e "────────────────────────────────────────────────────────"
if [[ $FAIL -eq 0 ]]; then
  echo -e "  ${GREEN}${BOLD}All required tests passed. Sprint 2 complete.${NC}"
else
  echo -e "  ${RED}${BOLD}$FAIL test(s) failed. See output above for details.${NC}"
fi
echo ""
exit $FAIL
