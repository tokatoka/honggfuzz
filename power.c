/*
 *
 * honggfuzz - power schedule calculation
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2025 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#include "power.h"

#include <time.h>

#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

/*
 * Compute structural complexity score (0-255) for differential fuzzing.
 * Complex inputs are more likely to exercise edge cases and trigger behavioral differences.
 *
 * Measures:
 * - Byte transition rate (many value changes = structured data)
 * - Size distribution (mid-size inputs tend to be more interesting)
 *
 * Performance: Uses sampling for large inputs (>4KB) to avoid O(n) overhead.
 */
unsigned power_ComputeComplexity(const uint8_t* restrict data, size_t len) {
    if (unlikely(len < 8)) {
        return 10;  /* Very small inputs have low complexity */
    }

    /*
     * For large inputs, sample instead of scanning all bytes.
     * Sample at most 4096 bytes, evenly distributed.
     */
    size_t sampleLen, stride;
    if (likely(len <= 4096)) {
        sampleLen = len;
        stride = 1;
    } else {
        stride = len >> 12;  /* len / 4096 */
        sampleLen = 4096;
    }

    /* Count byte value transitions (sampled) - unroll by 4 for better pipelining */
    unsigned transitions = 0;
    uint8_t prevByte = data[0];
    size_t idx = stride;
    size_t i = 1;
    
    /* Main loop - process 4 samples at a time when possible */
    size_t unrollLimit = (sampleLen > 4) ? sampleLen - 3 : 1;
    for (; i < unrollLimit && idx + stride * 3 < len; i += 4, idx += stride * 4) {
        uint8_t b0 = data[idx];
        uint8_t b1 = data[idx + stride];
        uint8_t b2 = data[idx + stride * 2];
        uint8_t b3 = data[idx + stride * 3];
        transitions += (b0 != prevByte) + (b1 != b0) + (b2 != b1) + (b3 != b2);
        prevByte = b3;
    }
    /* Handle remainder */
    for (; i < sampleLen && idx < len; i++, idx += stride) {
        uint8_t cur = data[idx];
        transitions += (cur != prevByte);
        prevByte = cur;
    }

    /* Transition rate: transitions per sampled byte, scaled to 0-100 */
    unsigned transitionRate = (transitions * 100) / (sampleLen - 1);

    /* Size score: favor mid-size inputs (64-4096 bytes) - use likely for common case */
    unsigned sizeScore;
    if (likely(len >= 64 && len <= 4096)) {
        sizeScore = 30;
    } else if (len >= 32 && len <= 8192) {
        sizeScore = 15;
    } else {
        sizeScore = 0;
    }

    /* Quick header check for structured data (protobuf/flatbuffer heuristics) */
    unsigned headerScore = 0;
    /* Common protobuf field tags: 0x08, 0x10, 0x12, 0x18, 0x1A, 0x20, 0x22 */
    uint8_t first = data[0];
    if ((first & 0x07) <= 2 && first >= 0x08 && first <= 0x7F) {
        headerScore = 20;  /* Likely protobuf */
    }
    /* Flatbuffer: often starts with size prefix or vtable offset */
    else if (len >= 8 && data[4] == 0 && data[5] == 0) {
        headerScore = 15;  /* Possible flatbuffer */
    }

    /* Combine scores, cap at 255 */
    unsigned complexity = transitionRate + sizeScore + headerScore;
    return (complexity < 255) ? complexity : 255;
}

#ifdef HF_USE_ENTROPY_SCHEDULE
/*
 * 0 = no entropy (single byte value), 100 = maximum entropy (uniform distribution).
 * Approximation of Shannon entropy.
 *
 * Performance: Uses sampling for large inputs (>4KB) to avoid O(n) overhead.
 */
unsigned power_ComputeEntropy(const uint8_t* restrict data, size_t len) {
    if (unlikely(len == 0)) {
        return 0;
    }

    /*
     * For large inputs, sample instead of scanning all bytes.
     * Sample at most 4096 bytes, evenly distributed.
     */
    size_t sampleLen, stride;
    if (likely(len <= 4096)) {
        sampleLen = len;
        stride = 1;
    } else {
        stride = len >> 12;  /* len / 4096 */
        sampleLen = 4096;
    }

    /* Use uint16_t for counts - sufficient for 4096 samples, better cache usage */
    uint16_t counts[256] = {0};
    
    /* Unroll counting loop by 4 for better throughput */
    size_t idx = 0;
    size_t i = 0;
    size_t unrollLimit = (sampleLen > 4) ? sampleLen - 3 : 0;
    for (; i < unrollLimit && idx + stride * 3 < len; i += 4, idx += stride * 4) {
        counts[data[idx]]++;
        counts[data[idx + stride]]++;
        counts[data[idx + stride * 2]]++;
        counts[data[idx + stride * 3]]++;
    }
    /* Handle remainder */
    for (; i < sampleLen && idx < len; i++, idx += stride) {
        counts[data[idx]]++;
    }

    /* Count unique bytes and find max count - unroll by 4 */
    unsigned unique = 0;
    uint16_t maxCnt = 0;
    for (unsigned j = 0; j < 256; j += 4) {
        uint16_t c0 = counts[j], c1 = counts[j+1], c2 = counts[j+2], c3 = counts[j+3];
        unique += (c0 > 0) + (c1 > 0) + (c2 > 0) + (c3 > 0);
        if (c0 > maxCnt) maxCnt = c0;
        if (c1 > maxCnt) maxCnt = c1;
        if (c2 > maxCnt) maxCnt = c2;
        if (c3 > maxCnt) maxCnt = c3;
    }

    if (unlikely(unique <= 1)) {
        return 0;
    }

    /*
     * * log2(unique) gives theoretical max entropy for this alphabet (0-8)
     * * Uniformity factor penalizes skewed distributions
     * Scaled to 0-100 range.
     */
    unsigned log2_unique = util_Log2(unique); /* 1-8 for unique 2-256 */
    unsigned log2_len    = util_Log2(sampleLen);

    /* Uniformity: ratio of average count to max count (scaled by 100) */
    uint32_t avgCnt     = (uint32_t)(sampleLen / unique);
    unsigned uniformity = (avgCnt * 100) / maxCnt; /* 0-100, higher = more uniform */

    /* Combine: entropy_score = log2(unique) * uniformity / 8 */
    /* log2_unique is 0-8, uniformity is 0-100, result scaled to 0-100 */
    unsigned entropy = (log2_unique * uniformity) >> 3;

    /* Boost if we're using a good portion of the alphabet relative to length */
    if (log2_unique >= log2_len) {
        entropy += 10;
        if (entropy > 100) entropy = 100;
    }

    return entropy;
}
#endif /* HF_USE_ENTROPY_SCHEDULE */

uint64_t power_calculateEnergy(run_t* run, dynfile_t* dynfile) {
    const uint64_t energyMax     = 32768;
    const time_t   freshTimeSec  = 60;
    const time_t   recentTimeSec = 300;
    const time_t   staleTimeSec  = 3600;

    uint64_t energy = POWER_BASE_ENERGY;
    time_t   now    = time(NULL);

    /* Cache stagnation time once - used in multiple places below */
    time_t lastCovUpdate = ATOMIC_GET(run->global->timing.lastCovUpdate);
    time_t stagnation    = now - lastCovUpdate;

    /* Cache commonly accessed fields to avoid repeated dereferencing */
    size_t   fileSize  = dynfile->size;
    uint64_t fileCov   = dynfile->cov[0];
    time_t   timeAdded = dynfile->timeAdded;

    /* Phase-aware energy - dry-run phase explores more, main phase exploits */
    fuzzState_t phase = run->global->feedback.state;
    if (unlikely(phase == _HF_STATE_DYNAMIC_DRY_RUN)) {
        /* During dry-run, favor smaller/faster inputs for quick exploration */
        if (fileSize < 256) {
            energy = (energy * 3) >> 1;
        }
    }

    /*
     * Novelty - inputs that discovered new edges explore unknown territory.
     * Decay novelty bonus over time - edges discovered 10+ minutes ago are less novel.
     */
    uint16_t newEdges = dynfile->newEdges;
    if (likely(newEdges > 0)) {
        time_t   age_mins = (now - timeAdded) / 60;
        uint32_t decay    = (age_mins < 10) ? 0 : HF_MIN(age_mins / 10, 6);
        uint32_t boost    = HF_MIN(newEdges, 8);
        if (likely(boost > decay)) {
            energy <<= (boost - decay);
        }
        /* Track when novelty decay reduces the boost */
        if (unlikely(decay > 0)) {
            ATOMIC_POST_INC(run->global->cnts.noveltyDecayApplied);
        }
    }

    /* Density - inputs with high coverage per byte are efficient */
    if (likely(fileSize > 0 && fileCov > 0)) {
        /* coverage / size * 100 */
        uint64_t density = (fileCov * 100) / fileSize;
        /* Heuristic - >50% instructions/bytes is good (small dense loops), >200% is amazing */
        if (density > 50) energy = (energy * 3) >> 1;
        if (unlikely(density > 200)) energy <<= 1;
    }

    /* Speed - faster inputs allow more mutations per second */
    uint64_t mutations = ATOMIC_GET(run->global->cnts.mutationsCnt);
    if (likely(mutations > 0)) {
        uint64_t elapsed   = (uint64_t)(now - run->global->timing.timeStart);
        uint64_t avg_usecs = elapsed > 0 ? (elapsed * 1000000ULL) / mutations : 1000;
        avg_usecs          = HF_CAP(avg_usecs, 100ULL, 10000000ULL);

        uint64_t exec_usecs  = HF_CAP(dynfile->timeExecUSecs, 100ULL, 10000000ULL);
        uint64_t speed_ratio = HF_CAP((avg_usecs << 4) / exec_usecs, 1ULL, 256ULL);
        energy               = (energy * speed_ratio) >> 4;
    }

    /* Fertility - inputs that produced children are in promising regions */
    uint32_t refs = ATOMIC_GET(dynfile->refs);
    if (refs > 0) {
        /* Logarithmic boost for fertility */
        energy = (energy * (8 + HF_MIN(util_Log2(refs + 1), 8))) >> 3;
    }

    /*
     * Mismatch fertility with saturation detection for differential fuzzing:
     * - mismatchRefs: descendants caused NEW UNIQUE mismatches => boost
     * - dupCrashRefs: descendants caused DUPLICATE crashes => penalize
     *
     * This prevents getting stuck finding the same mismatch repeatedly.
     * Only boost if we're finding more unique crashes than duplicates.
     */
    uint16_t mismatchRefs = ATOMIC_GET(dynfile->mismatchRefs);
    uint16_t dupCrashRefs = ATOMIC_GET(dynfile->dupCrashRefs);

    if (unlikely(mismatchRefs > 0 || dupCrashRefs > 0)) {
        if (mismatchRefs > dupCrashRefs) {
            /* Net positive: finding new mismatches, boost */
            uint16_t netGain = mismatchRefs - dupCrashRefs;
            uint32_t boost = HF_MIN(netGain, 4);
            energy <<= boost;
            /* Log and track first time we see significant mismatch fertility */
            if (unlikely(netGain >= 3 && ATOMIC_GET(dynfile->selectCnt) < 5)) {
                ATOMIC_POST_INC(run->global->cnts.diffFuzzFertileBoosts);
                LOG_I("[DIFF-FUZZ] Fertile lineage: idx=%zu unique=%u dup=%u boost=%ux",
                      dynfile->idx, mismatchRefs, dupCrashRefs, 1U << boost);
            }
        } else if (dupCrashRefs > mismatchRefs + 4) {
            /* Saturated: mostly duplicates, heavy penalty */
            uint16_t saturation = dupCrashRefs - mismatchRefs;
            uint32_t penalty = HF_MIN(saturation >> 2, 4);
            energy >>= penalty;
            /* Log and track when we first detect saturation (significant event) */
            if (unlikely(saturation >= 8 && ATOMIC_GET(dynfile->selectCnt) < 10)) {
                ATOMIC_POST_INC(run->global->cnts.diffFuzzSaturatedLineages);
                LOG_W("[DIFF-FUZZ] Saturated lineage detected: idx=%zu unique=%u dup=%u penalty=%ux",
                      dynfile->idx, mismatchRefs, dupCrashRefs, 1U << penalty);
            }
        }
        /* else: roughly balanced, no adjustment */
    }

    /* Freshness - time-based, newer inputs haven't been fully explored */
    time_t age_secs = now - timeAdded;
    if (unlikely(age_secs < freshTimeSec)) {
        energy <<= 2; /* added in last 60s - 4x */
        ATOMIC_POST_INC(run->global->cnts.freshInputBoosts);
    } else if (age_secs < recentTimeSec) {
        energy <<= 1; /* added in last 5 minutes - 2x */
    } else if (unlikely(age_secs > staleTimeSec && refs == 0)) {
        energy >>= 1; /* older than 60 min with no children - 0.5x */
        ATOMIC_POST_INC(run->global->cnts.staleInputPenalties);
    }

    /* Size - smaller inputs are faster and easier to analyze */
    if (unlikely(fileSize > 1024)) {
        uint32_t log_size = util_Log2(fileSize);
        if (log_size > 10) energy >>= HF_MIN(log_size - 10, 4);
    }

    /*
     * Stack depth - deeper execution paths suggest complex logic/recursion.
     * Boost energy for inputs causing deep stack usage.
     */
    uint64_t stackDepth = dynfile->stackDepth;
    if (unlikely(stackDepth > (1024 * 16))) { /* > 16KB */
        uint32_t stack_log = util_Log2(stackDepth >> 10);
        if (stack_log > 4) {
            /* Boost factor - 16KB->1x, 32KB->1.5x, 64KB->2x, 1MB->4x */
            energy = (energy * HF_MIN(stack_log - 2, 8)) >> 1;
        }
    }

    /* Execution path diversity - boost inputs with unique execution paths.
     * Critical for differential fuzzing - different paths = different behaviors. */
    uint64_t pathHash = dynfile->pathHash;
    if (pathHash != 0) {
        /* Always boost unique paths - they represent distinct behaviors */
        energy = (energy * 3) >> 1;  /* 50% boost */
        /* Extra boost for underexplored unique paths */
        uint32_t selectCntLocal = ATOMIC_GET(dynfile->selectCnt);
        if (unlikely(ATOMIC_GET(run->global->feedback.uniquePaths) > 100 && selectCntLocal < 10)) {
            energy <<= 1;  /* 2x for fresh unique paths */
        }
    }

    /* CMP progress - inputs making progress on comparisons are valuable */
    uint32_t cmpProgress = dynfile->cmpProgress;
    if (cmpProgress > 0) {
        uint32_t cmp_boost = HF_MIN(cmpProgress >> 3, 4);
        if (cmp_boost > 0) {
            energy = (energy * (4 + cmp_boost)) >> 2;
        }
    }

    /* Structural complexity - complex inputs exercise more edge cases.
     * Important for differential fuzzing - complex structures stress implementations. */
    uint8_t complexity = dynfile->complexity;
    if (unlikely(complexity > 100)) {
        /* Boost for highly structured inputs (complexity > 100) */
        energy = (energy * (8 + HF_MIN((complexity - 100) / 20, 4))) >> 3;
    }

    /* Rare edge bonus - inputs hitting edges seen by few corpus entries.
     * Critical for differential fuzzing - rare edges often hide implementation differences. */
    uint16_t rareEdgeCnt = dynfile->rareEdgeCnt;
    if (rareEdgeCnt > 0) {
        uint32_t rare_boost = HF_MIN(rareEdgeCnt, 16);
        /* Stronger boost: up to 3x for rare edge heavy inputs */
        energy = (energy * (8 + rare_boost)) >> 3;
        /* Extra boost during stagnation - focus on unexplored corners */
        if (unlikely(stagnation > 120 && rareEdgeCnt >= 4)) {
            energy <<= 1;  /* 2x bonus when stuck and hitting rare edges */
        }
    }

    /* Diminishing returns - inputs selected many times yield less */
    uint32_t selectCnt = ATOMIC_GET(dynfile->selectCnt);
    if (unlikely(selectCnt > 100)) {
        uint32_t penalty = HF_MIN(util_Log2(selectCnt / 100), 3);
        energy >>= penalty;
        ATOMIC_POST_INC(run->global->cnts.diminishingReturnsPenalties);
    }

    /*
     * Depth - deeply derived inputs may be over-specialized.
     * Progressive penalty - starts at depth 8, increases logarithmically.
     */
    uint8_t depth = dynfile->depth;
    if (unlikely(depth > 8)) {
        uint32_t depth_penalty = HF_MIN(util_Log2(depth - 7), 3);
        energy >>= depth_penalty;
        ATOMIC_POST_INC(run->global->cnts.depthPenalties);
    }

    /* Stagnation - focus on best inputs when stuck */
    if (unlikely(stagnation > 60)) {
        uint64_t maxCov = ATOMIC_GET(run->global->feedback.maxCov[0]);
        if (likely(maxCov > 0 && fileCov > 0)) {
            uint64_t pct = (fileCov * 100) / maxCov;
            if (pct >= 80)
                energy <<= 2; /* Boost high coverage */
            else if (unlikely(pct < 10))
                energy >>= 2; /* Penalize very low coverage */
        }
    }

#ifdef HF_USE_ENTROPY_SCHEDULE
    /* Entropy - penalize random blobs, boost structured data */
    if (likely(fileSize > 0)) {
        unsigned entropy = dynfile->entropy;
        if (unlikely(entropy > 93)) {
            energy >>= 1; /* High entropy (compressed/encrypted/random) - likely harder to fuzz */
        } else if (unlikely(entropy < 25)) {
            energy >>= 1; /* Very low entropy (sparse/zeros) - likely uninteresting */
        } else if (entropy < 62) {
            energy = (energy * 3) >> 1; /* Text/Structured data - boost */
        }
    }
#endif /* HF_USE_ENTROPY_SCHEDULE */

    /* Timeout - heavy penalty for timeout-causing inputs */
    if (unlikely(dynfile->timedout)) {
        energy >>= 5;
    }

    /* Convert energy to skip factor */
    energy = HF_CAP(energy, 1ULL, energyMax);

    /* Track energy statistics for decay validation */
    ATOMIC_POST_INC(run->global->cnts.energyCount);
    ATOMIC_POST_ADD(run->global->cnts.energySum, energy);
    
    /* Update min/max atomically (race-tolerant for observability) */
    uint64_t curMin = ATOMIC_GET(run->global->cnts.energyMin);
    if (energy < curMin || curMin == 0) {
        ATOMIC_SET(run->global->cnts.energyMin, energy);
    }
    uint64_t curMax = ATOMIC_GET(run->global->cnts.energyMax);
    if (energy > curMax) {
        ATOMIC_SET(run->global->cnts.energyMax, energy);
    }

    return energy;
}
