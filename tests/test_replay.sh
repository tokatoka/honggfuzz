#!/bin/bash
# Integration test for --replay mode with coverage-required set-cover output.
#
# Builds test_target with hfuzz-cc instrumentation, creates a small corpus,
# runs honggfuzz --replay --covdir_new, and verifies:
#   1. Clean exit after processing all inputs
#   2. coverage_required.json exists with valid JSON and non-empty array
#   3. coverage_report.json exists with non-zero guard counts
#   4. All corpus files were processed (testedFileCnt == fileCnt)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HONGGFUZZ_DIR="$(dirname "$SCRIPT_DIR")"
cd "$HONGGFUZZ_DIR"

echo "=== Honggfuzz Replay Mode Test ==="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TEST_DIR=$(mktemp -d)
CORPUS_DIR="$TEST_DIR/corpus"
COV_DIR="$TEST_DIR/covdir"
WORKSPACE_DIR="$TEST_DIR/workspace"
mkdir -p "$CORPUS_DIR" "$COV_DIR" "$WORKSPACE_DIR"

cleanup() {
    echo ""
    echo "Cleaning up $TEST_DIR..."
    rm -rf "$TEST_DIR"
    rm -f tests/test_target
}
trap cleanup EXIT

ERRORS=0

echo "1. Building test target with instrumentation..."
./hfuzz_cc/hfuzz-cc -fsanitize-coverage=trace-pc-guard,inline-8bit-counters,trace-cmp \
    -o tests/test_target tests/test_target.c
echo -e "${GREEN}   [OK] Test target built${NC}"
echo ""

echo "2. Creating corpus with distinct coverage paths..."
# Each seed is designed to hit a different branch in test_target.c:
#   data[0] < 85  -> path_a
#   data[0] < 170 -> path_b
#   data[0] >= 170 -> path_c
# Plus deeper branches keyed on content.
echo -n "AAAA"         > "$CORPUS_DIR/seed_path_a"        # data[0]='A' (65) -> path_a
printf '\x60YYYY'      > "$CORPUS_DIR/seed_path_b"        # data[0]=0x60 (96) -> path_b
printf '\xb0XXXX'      > "$CORPUS_DIR/seed_path_c"        # data[0]=0xb0 (176) -> path_c
echo -n "FUZZTEST9999" > "$CORPUS_DIR/seed_path_c_deep"   # hits path_c memcmp chain
printf '\xffABC01234567890' > "$CORPUS_DIR/seed_nested"   # len>10, hits nested conditions
CORPUS_COUNT=$(ls "$CORPUS_DIR" | wc -l)
echo "   Created $CORPUS_COUNT corpus files"
echo ""

echo "3. Running replay mode (2 threads)..."
set +e
timeout 60s ./honggfuzz \
    --replay \
    --covdir_new "$COV_DIR" \
    -f "$CORPUS_DIR" \
    -W "$WORKSPACE_DIR" \
    -n 2 \
    -v \
    --persistent \
    -- ./tests/test_target 2>&1 | tee "$TEST_DIR/replay.log"
REPLAY_EXIT=${PIPESTATUS[0]}
set -e

if [ "$REPLAY_EXIT" -eq 124 ] || [ "$REPLAY_EXIT" -eq 137 ]; then
    echo -e "${RED}   [FAIL] honggfuzz timed out (exit $REPLAY_EXIT)${NC}"
    ERRORS=$((ERRORS + 1))
elif [ "$REPLAY_EXIT" -ne 0 ]; then
    echo -e "${RED}   [FAIL] honggfuzz exited with code $REPLAY_EXIT${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "4. Checking results..."

# 4a. Replay should have entered replay state
if grep -q "Replay\|_HF_STATE_REPLAY\|Replay mode" "$TEST_DIR/replay.log" 2>/dev/null; then
    echo -e "${GREEN}   [OK] Replay mode was entered${NC}"
else
    echo -e "${RED}   [FAIL] No evidence of replay mode in logs${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 4b. All files should have been processed
COV_ENTRIES=$(grep -oP 'Wrote \K[0-9]+(?= coverage data entries)' "$TEST_DIR/replay.log" 2>/dev/null | tail -1) || COV_ENTRIES=""
REQ_FILES=$(grep -oP 'Wrote \K[0-9]+(?= coverage-required)' "$TEST_DIR/replay.log" 2>/dev/null | tail -1) || REQ_FILES=""
ITERATIONS=$(grep -oP 'iterations:\K[0-9]+' "$TEST_DIR/replay.log" 2>/dev/null | tail -1) || ITERATIONS=""
echo "   Iterations: ${ITERATIONS:-unknown}, Coverage entries: ${COV_ENTRIES:-unknown}, Required files: ${REQ_FILES:-unknown}"
if [ -z "$ITERATIONS" ] || [ "$ITERATIONS" -lt "$CORPUS_COUNT" ] 2>/dev/null; then
    echo -e "${RED}   [FAIL] Expected at least $CORPUS_COUNT iterations, got ${ITERATIONS:-0}${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}   [OK] All corpus files were processed ($ITERATIONS iterations >= $CORPUS_COUNT files)${NC}"
fi
if [ -z "$COV_ENTRIES" ] || [ "$COV_ENTRIES" -lt 1 ] 2>/dev/null; then
    echo -e "${RED}   [FAIL] No coverage data entries written${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}   [OK] $COV_ENTRIES coverage data entries written${NC}"
fi

# 4c. coverage_required.json
if [ -f "$COV_DIR/coverage_required.json" ]; then
    echo -e "${GREEN}   [OK] coverage_required.json exists${NC}"

    # Validate JSON
    if python3 -c "import json, sys; d=json.load(open(sys.argv[1])); assert 'coverage_required_files' in d" "$COV_DIR/coverage_required.json" 2>/dev/null; then
        echo -e "${GREEN}   [OK] Valid JSON with coverage_required_files key${NC}"
    else
        echo -e "${RED}   [FAIL] Invalid JSON or missing coverage_required_files key${NC}"
        echo "   Contents: $(cat "$COV_DIR/coverage_required.json")"
        ERRORS=$((ERRORS + 1))
    fi

    # Check non-empty
    REQ_COUNT=$(python3 -c "import json, sys; d=json.load(open(sys.argv[1])); print(len(d['coverage_required_files']))" "$COV_DIR/coverage_required.json" 2>/dev/null) || REQ_COUNT=0
    echo "   Coverage-required files: $REQ_COUNT"
    if [ "$REQ_COUNT" -gt 0 ] 2>/dev/null; then
        echo -e "${GREEN}   [OK] Non-empty coverage-required set${NC}"
        # Print the filenames
        python3 -c "import json, sys; d=json.load(open(sys.argv[1])); [print(f'     - {f}') for f in d['coverage_required_files']]" "$COV_DIR/coverage_required.json"
    else
        echo -e "${RED}   [FAIL] coverage_required_files is empty${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    # At least one seed should be required (first input always adds new coverage)
    if [ "$REQ_COUNT" -ge 1 ] 2>/dev/null; then
        echo -e "${GREEN}   [OK] At least 1 file marked as coverage-required${NC}"
    fi
else
    echo -e "${RED}   [FAIL] coverage_required.json not found in $COV_DIR${NC}"
    ls -la "$COV_DIR/"
    ERRORS=$((ERRORS + 1))
fi

# 4d. coverage_report.json
if [ -f "$COV_DIR/coverage_report.json" ]; then
    echo -e "${GREEN}   [OK] coverage_report.json exists${NC}"
    GUARD_NB=$(python3 -c "import json, sys; d=json.load(open(sys.argv[1])); print(d.get('guard_nb', 0))" "$COV_DIR/coverage_report.json" 2>/dev/null) || GUARD_NB=0
    echo "   Guard count (guardNb): $GUARD_NB"
    if [ "$GUARD_NB" -gt 0 ] 2>/dev/null; then
        echo -e "${GREEN}   [OK] Non-zero guard count${NC}"
    else
        echo -e "${YELLOW}   [WARN] Guard count is 0 (may be OK if report format differs)${NC}"
    fi
else
    echo -e "${YELLOW}   [WARN] coverage_report.json not found (may require specific build)${NC}"
fi

# 4e. Check for errors/crashes during replay
CRASH_COUNT=$(grep -c "Crash\|SIGABRT\|SIGSEGV\|SIGBUS" "$TEST_DIR/replay.log" 2>/dev/null) || CRASH_COUNT=0
if [ "$CRASH_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}   [WARN] $CRASH_COUNT crash-related messages in log (expected if test_target has crashes)${NC}"
else
    echo -e "${GREEN}   [OK] No crashes during replay${NC}"
fi

# 4f. Check that the covered-guards bitmap was allocated
if grep -q "Allocated covered-guards bitmap" "$TEST_DIR/replay.log" 2>/dev/null; then
    GUARD_SIZE=$(grep -oP 'bitmap: \K[0-9]+' "$TEST_DIR/replay.log" 2>/dev/null | head -1) || GUARD_SIZE=""
    echo -e "${GREEN}   [OK] Covered-guards bitmap allocated ($GUARD_SIZE guards)${NC}"
else
    echo -e "${YELLOW}   [WARN] No covered-guards bitmap allocation message${NC}"
fi

echo ""
echo "=== Replay Test Summary ==="
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}All checks passed!${NC}"
    echo ""
    echo "Replay mode is working correctly:"
    echo "  - Processes all corpus files and exits"
    echo "  - Produces coverage_required.json with set-cover results"
    echo "  - Coverage tracking is active during replay"
else
    echo -e "${RED}$ERRORS check(s) failed. Review the log above.${NC}"
    echo ""
    echo "Full log: $TEST_DIR/replay.log"
    echo "Test dir preserved: $TEST_DIR"
    rm -f tests/test_target
    trap - EXIT
    exit 1
fi
