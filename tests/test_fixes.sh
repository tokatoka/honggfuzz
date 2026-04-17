#!/bin/bash
# Test script for verifying PC guard and synchronization fixes
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HONGGFUZZ_DIR="$(dirname "$SCRIPT_DIR")"
cd "$HONGGFUZZ_DIR"

echo "=== Honggfuzz Cross-Process Synchronization Test ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Setup
TEST_DIR=$(mktemp -d)
CORPUS_DIR="$TEST_DIR/corpus"
WORKSPACE_DIR="$TEST_DIR/workspace"
mkdir -p "$CORPUS_DIR" "$WORKSPACE_DIR"

# Create initial seed
echo "seed" > "$CORPUS_DIR/seed"

cleanup() {
    echo ""
    echo "Cleaning up $TEST_DIR..."
    rm -rf "$TEST_DIR"
    rm -f tests/test_target
}
trap cleanup EXIT

echo "1. Building test target with instrumentation..."
./hfuzz_cc/hfuzz-cc -fsanitize-coverage=trace-pc-guard,inline-8bit-counters,trace-cmp \
    -o tests/test_target tests/test_target.c
echo -e "${GREEN}   [OK] Test target built${NC}"
echo ""

echo "2. Running short fuzz test (30 seconds, 4 threads)..."
echo "   Watch for:"
echo "   - 'PC-Guard module registration' messages (new modules)"
echo "   - 'Reusing guards for module' messages (guard reuse working)"
echo "   - No 'PC-guard limit exceeded' errors"
echo "   - Edge count should stabilize (not grow infinitely)"
echo ""

# Run fuzzer with verbose output
timeout 30s ./honggfuzz \
    -f "$CORPUS_DIR" \
    -W "$WORKSPACE_DIR" \
    -n 4 \
    -v \
    --persistent \
    -- ./tests/test_target 2>&1 | tee "$TEST_DIR/fuzz.log" || true

echo ""
echo "3. Analyzing results..."

# Check for guard reuse messages
REUSE_COUNT=$(grep -c "Reusing guards for module\|Reusing 8-bit guards" "$TEST_DIR/fuzz.log" 2>/dev/null) || REUSE_COUNT=0
REG_COUNT=$(grep -c "module registration" "$TEST_DIR/fuzz.log" 2>/dev/null) || REG_COUNT=0
ERROR_COUNT=$(grep -c "limit exceeded\|No free tracking slots" "$TEST_DIR/fuzz.log" 2>/dev/null) || ERROR_COUNT=0

echo "   Module registrations: $REG_COUNT"
echo "   Guard reuses: $REUSE_COUNT"
echo "   Errors: $ERROR_COUNT"

if [ "${ERROR_COUNT:-0}" -gt 0 ]; then
    echo -e "${RED}   [FAIL] Found limit exceeded errors!${NC}"
    grep "limit exceeded\|No free tracking slots" "$TEST_DIR/fuzz.log"
    exit 1
fi

if [ "${REG_COUNT:-0}" -gt 0 ]; then
    echo -e "${GREEN}   [OK] Module registration working${NC}"
else
    echo -e "${YELLOW}   [WARN] No module registration messages (may be OK if not verbose)${NC}"
fi

# Extract final edge count
FINAL_EDGES=$(grep -oP "edge: \K[0-9,]+" "$TEST_DIR/fuzz.log" | tail -1 | tr -d ',')
if [ -n "$FINAL_EDGES" ]; then
    echo "   Final edge count: $FINAL_EDGES"
    echo -e "${GREEN}   [OK] Coverage tracking working${NC}"
fi

# Verify all coverage signals are wired and firing
if grep -q "(i/b/h/e/p/c/eb)" "$TEST_DIR/fuzz.log" 2>/dev/null; then
    echo -e "${GREEN}   [OK] Log format contains (i/b/h/e/p/c/eb)${NC}"
else
    echo -e "${RED}   [FAIL] Log format missing (i/b/h/e/p/c/eb) -- edge bucket not wired${NC}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
fi
# Cur: fields are i/b/h/e/p/c/eb -- check cumulative edge (4th), cmp (6th), eb (7th)
CUR_EDGE=$(grep -oP 'Cur:\K[0-9/]+' "$TEST_DIR/fuzz.log" 2>/dev/null | \
    awk -F'/' '{print $4}' | sort -rn | head -1) || CUR_EDGE=0
CUR_CMP=$(grep -oP 'Cur:\K[0-9/]+' "$TEST_DIR/fuzz.log" 2>/dev/null | \
    awk -F'/' '{print $6}' | sort -rn | head -1) || CUR_CMP=0
CUR_EB=$(grep -oP 'Cur:\K[0-9/]+' "$TEST_DIR/fuzz.log" 2>/dev/null | \
    awk -F'/' '{print $7}' | sort -rn | head -1) || CUR_EB=0
echo "   Coverage signals -- edge: ${CUR_EDGE:-0}, cmp: ${CUR_CMP:-0}, eb: ${CUR_EB:-0}"
if [ "${CUR_EDGE:-0}" -gt 0 ] 2>/dev/null; then
    echo -e "${GREEN}   [OK] Edge signal (pidNewEdge) firing${NC}"
else
    echo -e "${RED}   [FAIL] Edge signal is 0 -- pidNewEdge not reaching fuzz loop${NC}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
fi
if [ "${CUR_CMP:-0}" -gt 0 ] 2>/dev/null; then
    echo -e "${GREEN}   [OK] CMP signal (pidNewCmp) firing${NC}"
else
    echo -e "${YELLOW}   [WARN] CMP signal is 0 (may need trace-cmp instrumentation)${NC}"
fi
if [ "${CUR_EB:-0}" -gt 0 ] 2>/dev/null; then
    echo -e "${GREEN}   [OK] Edge bucket signal (pidEdgeBucketInc) firing${NC}"
else
    echo -e "${YELLOW}   [WARN] Edge bucket signal is 0 (may need longer run)${NC}"
fi

echo ""
echo "4. Checking for race condition indicators..."

# Look for suspicious patterns
TIMEOUT_ERRORS=$(grep -c "Spinlock timeout" "$TEST_DIR/fuzz.log" 2>/dev/null) || TIMEOUT_ERRORS=0
if [ "${TIMEOUT_ERRORS:-0}" -gt 0 ]; then
    echo -e "${YELLOW}   [WARN] Spinlock timeouts detected: $TIMEOUT_ERRORS (may indicate contention)${NC}"
else
    echo -e "${GREEN}   [OK] No spinlock timeouts${NC}"
fi

echo ""
echo "=== Test Summary ==="
if [ "${ERROR_COUNT:-0}" -eq 0 ]; then
    echo -e "${GREEN}All checks passed!${NC}"
    echo ""
    echo "The fixes appear to be working correctly:"
    echo "  - Guard allocation is synchronized across processes"
    echo "  - Module tracking prevents guard leaks"
    echo "  - No overflow errors detected"
else
    echo -e "${RED}Some checks failed. Review the log above.${NC}"
    exit 1
fi

