#!/bin/bash
# Stress test for race conditions in guard allocation
# Tests both PC guards and 8-bit counters under heavy concurrency
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HONGGFUZZ_DIR="$(dirname "$SCRIPT_DIR")"
cd "$HONGGFUZZ_DIR"

echo "=== Stress Test: Cross-Process Guard Allocation ==="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

# Build test targets if needed
echo "1. Building test targets..."
if [ ! -f tests/test_target_pcguard ]; then
    ./hfuzz_cc/hfuzz-cc -fsanitize-coverage=trace-pc-guard,trace-cmp \
        -o tests/test_target_pcguard tests/test_target.c
fi
if [ ! -f tests/test_target_8bit ]; then
    ./hfuzz_cc/hfuzz-cc -fsanitize-coverage=inline-8bit-counters,trace-cmp \
        -o tests/test_target_8bit tests/test_target.c
fi
echo -e "${GREEN}   [OK] Test targets built${NC}"
echo ""

TEST_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Test 1: High thread count stress test
echo "2. High concurrency test (16 threads, PC guards)..."
CORPUS="$TEST_DIR/corpus1"
WORKSPACE="$TEST_DIR/ws1"
mkdir -p "$CORPUS" "$WORKSPACE"
echo "seed" > "$CORPUS/seed"

OUTPUT=$(timeout 15s ./honggfuzz \
    -f "$CORPUS" -W "$WORKSPACE" -n 16 -v --persistent \
    -- ./tests/test_target_pcguard 2>&1 || true)

if echo "$OUTPUT" | grep -q "limit exceeded\|No free tracking"; then
    echo -e "${RED}   [FAIL] Overflow error detected${NC}"
    ERRORS=$((ERRORS + 1))
else
    REG_COUNT=$(echo "$OUTPUT" | grep -c "module registration" 2>/dev/null) || REG_COUNT=0
    REUSE_COUNT=$(echo "$OUTPUT" | grep -c "Reusing.*guards" 2>/dev/null) || REUSE_COUNT=0
    TIMEOUT_COUNT=$(echo "$OUTPUT" | grep -c "Spinlock timeout" 2>/dev/null) || TIMEOUT_COUNT=0
    
    echo "   Registrations: $REG_COUNT, Reuses: $REUSE_COUNT, Timeouts: $TIMEOUT_COUNT"
    
    if [ "${TIMEOUT_COUNT:-0}" -gt 0 ]; then
        echo -e "${YELLOW}   [WARN] Spinlock timeouts detected (contention)${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
    
    # Should only register once, then reuse
    if [ "${REG_COUNT:-0}" -gt 0 ] && [ "${REUSE_COUNT:-0}" -gt 0 ]; then
        echo -e "${GREEN}   [OK] Guard reuse working${NC}"
    elif [ "${REG_COUNT:-0}" -eq 0 ]; then
        echo -e "${YELLOW}   [WARN] No registration messages (run with -v?)${NC}"
        WARNINGS=$((WARNINGS + 1))
    else
        echo -e "${GREEN}   [OK] No errors${NC}"
    fi
fi
echo ""

# Test 2: 8-bit counters stress test
echo "3. High concurrency test (16 threads, 8-bit counters)..."
CORPUS="$TEST_DIR/corpus2"
WORKSPACE="$TEST_DIR/ws2"
mkdir -p "$CORPUS" "$WORKSPACE"
echo "seed" > "$CORPUS/seed"

OUTPUT=$(timeout 15s ./honggfuzz \
    -f "$CORPUS" -W "$WORKSPACE" -n 16 -v --persistent \
    -- ./tests/test_target_8bit 2>&1 || true)

if echo "$OUTPUT" | grep -q "limit exceeded\|No free tracking"; then
    echo -e "${RED}   [FAIL] Overflow error detected${NC}"
    ERRORS=$((ERRORS + 1))
else
    REG_8BIT=$(echo "$OUTPUT" | grep -c "8-bit module registration" 2>/dev/null) || REG_8BIT=0
    echo "   8-bit registrations: $REG_8BIT"
    
    if [ "${REG_8BIT:-0}" -gt 0 ]; then
        echo -e "${GREEN}   [OK] 8-bit counter tracking working${NC}"
    else
        echo -e "${YELLOW}   [WARN] No 8-bit registration messages${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
fi
echo ""

# Test 3: Rapid restart cycles (stress module re-registration)
echo "4. Rapid restart stress test (10 cycles, 8 threads each)..."
RESTART_ERRORS=0
for i in $(seq 1 10); do
    CORPUS="$TEST_DIR/restart_$i"
    WORKSPACE="$TEST_DIR/ws_restart_$i"
    mkdir -p "$CORPUS" "$WORKSPACE"
    echo "seed$i" > "$CORPUS/seed"
    
    if timeout 3s ./honggfuzz \
        -f "$CORPUS" -W "$WORKSPACE" -n 8 --persistent \
        -- ./tests/test_target_pcguard 2>&1 | grep -q "limit exceeded\|No free tracking"; then
        RESTART_ERRORS=$((RESTART_ERRORS + 1))
    fi
done

if [ "$RESTART_ERRORS" -gt 0 ]; then
    echo -e "${RED}   [FAIL] $RESTART_ERRORS/10 restart cycles had errors${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}   [OK] All 10 restart cycles passed${NC}"
fi
echo ""

# Test 4: Guard count stability check
echo "5. Guard count stability test..."
CORPUS="$TEST_DIR/stability"
WORKSPACE="$TEST_DIR/ws_stability"
mkdir -p "$CORPUS" "$WORKSPACE"
echo "seed" > "$CORPUS/seed"

# Run for 10 seconds and collect guard counts
GUARD_COUNTS=$(timeout 10s ./honggfuzz \
    -f "$CORPUS" -W "$WORKSPACE" -n 4 -v --persistent \
    -- ./tests/test_target_pcguard 2>&1 | \
    grep -oP "at guard \K[0-9]+" | sort -n | uniq || echo "")

if [ -n "$GUARD_COUNTS" ]; then
    UNIQUE_BASES=$(echo "$GUARD_COUNTS" | wc -l)
    echo "   Unique guard bases seen: $UNIQUE_BASES"
    
    # Should only see 1-2 unique base values (one per module type)
    if [ "$UNIQUE_BASES" -le 3 ]; then
        echo -e "${GREEN}   [OK] Guard allocation stable${NC}"
    else
        echo -e "${RED}   [FAIL] Too many unique guard bases ($UNIQUE_BASES) - possible leak!${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${YELLOW}   [WARN] Could not extract guard counts${NC}"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# Summary
echo "=== Results ==="
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"
echo ""

if [ "$ERRORS" -eq 0 ]; then
    if [ "$WARNINGS" -gt 0 ]; then
        echo -e "${YELLOW}All tests passed with $WARNINGS warning(s)${NC}"
    else
        echo -e "${GREEN}All tests passed!${NC}"
    fi
    exit 0
else
    echo -e "${RED}$ERRORS test(s) failed${NC}"
    exit 1
fi
