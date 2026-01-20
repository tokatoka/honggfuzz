/*
 * Simple test target for verifying PC guard and 8-bit counter fixes.
 * Compile with: hfuzz_cc/hfuzz-cc -o test_target test_target.c
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Create multiple code paths to generate many PC guards */
int path_a(const uint8_t* data, size_t len) {
    int sum = 0;
    for (size_t i = 0; i < len && i < 100; i++) {
        if (data[i] == 'A') sum += 1;
        else if (data[i] == 'B') sum += 2;
        else if (data[i] == 'C') sum += 3;
        else sum += data[i];
    }
    return sum;
}

int path_b(const uint8_t* data, size_t len) {
    int product = 1;
    for (size_t i = 0; i < len && i < 50; i++) {
        if (data[i] > 128) product *= 2;
        else product += 1;
    }
    return product;
}

int path_c(const uint8_t* data, size_t len) {
    /* Comparison-heavy to test CMP tracking */
    if (len >= 4 && memcmp(data, "FUZZ", 4) == 0) {
        if (len >= 8 && memcmp(data + 4, "TEST", 4) == 0) {
            return 999;
        }
        return 100;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    if (len == 0) return 0;
    
    int result = 0;
    
    /* Exercise multiple paths based on input */
    if (data[0] < 85) {
        result += path_a(data, len);
    } else if (data[0] < 170) {
        result += path_b(data, len);
    } else {
        result += path_c(data, len);
    }
    
    /* Nested conditions to create more edges */
    if (len > 10) {
        if (data[1] == 0x41) result += 10;
        if (data[2] == 0x42) result += 20;
        if (data[3] == 0x43) result += 30;
    }
    
    return 0;
}

