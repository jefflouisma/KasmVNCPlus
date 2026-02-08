#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# KasmVNC Plus — E2E Test Runner
# ═══════════════════════════════════════════════════════════════════════════════
# Runs API tests first, then Browser tests, sharing cookies/session state.
# Evidence is output to tests/output/ with PT timestamps.
#
# Usage:
#   ./tests/run_all.sh                    # Run all tests
#   ./tests/run_all.sh --api-only         # Run API tests only
#   ./tests/run_all.sh --browser-only     # Run browser tests only
#   ./tests/run_all.sh -k "test_1_1"      # Run specific test(s)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$SCRIPT_DIR/.venv"

# ─── PT Timestamp ────────────────────────────────────────────────────────────
TIMESTAMP=$(TZ="America/Los_Angeles" date +"%Y-%m-%d_%I-%M-%S_%p_PT")
OUTPUT_DIR="$SCRIPT_DIR/output/$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}    KasmVNC Plus — E2E Test Suite${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  Timestamp: ${YELLOW}$TIMESTAMP${NC}"
echo -e "  Output:    ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "  Base URL:  ${YELLOW}${KASMVNC_URL:-http://localhost:8888}${NC}"
echo ""

# ─── Activate venv ───────────────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${RED}ERROR: Virtual environment not found at $VENV_DIR${NC}"
    echo -e "Run: python3 -m venv $VENV_DIR && source $VENV_DIR/bin/activate && pip install playwright pytest-playwright requests && playwright install chromium"
    exit 1
fi

source "$VENV_DIR/bin/activate"

# ─── Parse arguments ────────────────────────────────────────────────────────
API_ONLY=false
BROWSER_ONLY=false
EXTRA_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --api-only)    API_ONLY=true ;;
        --browser-only) BROWSER_ONLY=true ;;
        *)             EXTRA_ARGS+=("$arg") ;;
    esac
done

# ─── Pre-flight: check server is reachable ───────────────────────────────────
BASE_URL="${KASMVNC_URL:-http://localhost:8888}"
echo -e "${CYAN}Pre-flight check...${NC}"
if curl -s --connect-timeout 5 -o /dev/null "$BASE_URL/healthz" 2>/dev/null; then
    echo -e "  ${GREEN}✅ Server reachable at $BASE_URL${NC}"
else
    echo -e "  ${RED}❌ Server NOT reachable at $BASE_URL${NC}"
    echo -e "  ${YELLOW}Continuing anyway — tests will report failures.${NC}"
fi
echo ""

# ─── Run API Tests ───────────────────────────────────────────────────────────
API_EXIT=0
if [ "$BROWSER_ONLY" = false ]; then
    echo -e "${BOLD}── Phase 1: API Tests (Groups 1, 2, 5) ──${NC}"
    pytest "$SCRIPT_DIR/test_api.py" \
        -v --tb=short --no-header \
        --junit-xml="$OUTPUT_DIR/api_results.xml" \
        "${EXTRA_ARGS[@]}" \
        2>&1 | tee "$OUTPUT_DIR/api_console.log" || API_EXIT=$?

    if [ $API_EXIT -eq 0 ]; then
        echo -e "\n  ${GREEN}✅ API Tests: ALL PASSED${NC}\n"
    else
        echo -e "\n  ${RED}❌ API Tests: SOME FAILED (exit code $API_EXIT)${NC}\n"
    fi
fi

# ─── Run Browser Tests ──────────────────────────────────────────────────────
BROWSER_EXIT=0
if [ "$API_ONLY" = false ]; then
    echo -e "${BOLD}── Phase 2: Browser Tests (Groups 3, 4, 6) ──${NC}"
    pytest "$SCRIPT_DIR/test_browser.py" \
        -v --tb=short --no-header \
        --browser chromium \
        --junit-xml="$OUTPUT_DIR/browser_results.xml" \
        "${EXTRA_ARGS[@]}" \
        2>&1 | tee "$OUTPUT_DIR/browser_console.log" || BROWSER_EXIT=$?

    if [ $BROWSER_EXIT -eq 0 ]; then
        echo -e "\n  ${GREEN}✅ Browser Tests: ALL PASSED${NC}\n"
    else
        echo -e "\n  ${RED}❌ Browser Tests: SOME FAILED (exit code $BROWSER_EXIT)${NC}\n"
    fi
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
OVERALL_EXIT=$((API_EXIT + BROWSER_EXIT))
if [ $OVERALL_EXIT -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}ALL TESTS PASSED ✅${NC}"
else
    echo -e "  ${RED}${BOLD}SOME TESTS FAILED ❌${NC}"
fi
echo -e "  Evidence:  ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "  Timestamp: ${YELLOW}$TIMESTAMP${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"

# ─── Copy summary if conftest produced one ───────────────────────────────────
# The conftest.py results_log fixture writes summary.txt and results.json
# to the output_dir it creates (which may differ from ours).
# Let's also capture the combined exit status.
echo "$OVERALL_EXIT" > "$OUTPUT_DIR/exit_code"
echo "API: exit=$API_EXIT, Browser: exit=$BROWSER_EXIT" > "$OUTPUT_DIR/run_summary.txt"
echo "Timestamp: $TIMESTAMP" >> "$OUTPUT_DIR/run_summary.txt"
echo "Total exit: $OVERALL_EXIT" >> "$OUTPUT_DIR/run_summary.txt"

exit $OVERALL_EXIT
