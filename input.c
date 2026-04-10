/*
 * honggfuzz - file operations
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2020 by Google Inc. All Rights Reserved.
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

#include "input.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dict.h"
#include "fuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "mangle.h"
#include "power.h"
#include "subproc.h"
#include "hfuzz_metrics.h"

void input_setSize(run_t* run, size_t sz) {
    if (run->dynfile->size == sz) {
        return;
    }
    if (sz > run->global->mutate.maxInputSz) {
        PLOG_F("Too large size requested: %zu > maxSize: %zu", sz, run->global->mutate.maxInputSz);
    }
    /* ftruncate of a mmaped file fails under CygWin, it's also painfully slow under MacOS X */
#if !defined(__CYGWIN__) && !defined(_HF_ARCH_DARWIN)
    if (TEMP_FAILURE_RETRY(ftruncate(run->dynfile->fd, sz)) == -1) {
        PLOG_W("ftruncate(run->dynfile->fd=%d, sz=%zu)", run->dynfile->fd, sz);
    }
#endif /* !defined(__CYGWIN__) && !defined(_HF_ARCH_DARWIN) */
    run->dynfile->size = sz;
}

bool input_getDirStatsAndRewind(honggfuzz_t* hfuzz) {
    rewinddir(hfuzz->io.inputDirPtr);

    size_t fileCnt = 0U;
    for (;;) {
        errno                = 0;
        struct dirent* entry = readdir(hfuzz->io.inputDirPtr);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir('%s')", hfuzz->io.inputDir);
            return false;
        }
        if (entry == NULL) {
            break;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", hfuzz->io.inputDir, entry->d_name);

        LOG_D("Analyzing file '%s'", path);

        struct stat st;
        if (stat(path, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", path);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", path);
            continue;
        }
        if (hfuzz->io.maxFileSz && st.st_size > (off_t)hfuzz->io.maxFileSz) {
            LOG_D("File '%s' is bigger than maximal defined file size (-F): %" PRIu64 " > %zu",
                path, (uint64_t)st.st_size, hfuzz->io.maxFileSz);
        }
        if ((size_t)st.st_size > hfuzz->mutate.maxInputSz) {
            hfuzz->mutate.maxInputSz = st.st_size;
        }
        fileCnt++;
    }

    hfuzz->io.fileCnt = fileCnt;
    if (hfuzz->io.maxFileSz) {
        hfuzz->mutate.maxInputSz = hfuzz->io.maxFileSz;
    } else if (hfuzz->mutate.maxInputSz < _HF_INPUT_DEFAULT_SIZE) {
        hfuzz->mutate.maxInputSz = _HF_INPUT_DEFAULT_SIZE;
    } else if (hfuzz->mutate.maxInputSz > _HF_INPUT_MAX_SIZE) {
        hfuzz->mutate.maxInputSz = _HF_INPUT_MAX_SIZE;
    }

    if (hfuzz->io.fileCnt == 0U) {
        LOG_W("No usable files in the input directory '%s'", hfuzz->io.inputDir);
    }

    LOG_D("Analyzed '%s' directory: maxInputSz:%zu, number of usable files:%zu", hfuzz->io.inputDir,
        hfuzz->mutate.maxInputSz, hfuzz->io.fileCnt);

    rewinddir(hfuzz->io.inputDirPtr);

    return true;
}

bool input_getNext(run_t* run, char fname[PATH_MAX], size_t* len, bool rewind) {
    MX_SCOPED_LOCK(&run->global->mutex.input);

    if (run->global->io.fileCnt == 0U) {
        LOG_W("No useful files in the input directory");
        return false;
    }

    for (;;) {
        errno                = 0;
        struct dirent* entry = readdir(run->global->io.inputDirPtr);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir_r('%s')", run->global->io.inputDir);
            return false;
        }
        if (entry == NULL && !rewind) {
            return false;
        }
        if (entry == NULL && rewind) {
            rewinddir(run->global->io.inputDirPtr);
            continue;
        }
        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "%s/%s", run->global->io.inputDir, entry->d_name);
        struct stat st;
        if (stat(path, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", path);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", path);
            continue;
        }

        snprintf(fname, PATH_MAX, "%s", entry->d_name);
        *len = st.st_size;
        return true;
    }
}

bool input_init(honggfuzz_t* hfuzz) {
    hfuzz->io.fileCnt = 0U;

    if (!hfuzz->io.inputDir) {
        LOG_W("No input file/dir specified");
        return false;
    }

    int dir_fd = TEMP_FAILURE_RETRY(open(hfuzz->io.inputDir, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (dir_fd == -1) {
        PLOG_W("open('%s', O_DIRECTORY|O_RDONLY|O_CLOEXEC)", hfuzz->io.inputDir);
        return false;
    }
    if ((hfuzz->io.inputDirPtr = fdopendir(dir_fd)) == NULL) {
        PLOG_W("fdopendir(dir='%s', fd=%d)", hfuzz->io.inputDir, dir_fd);
        close(dir_fd);
        return false;
    }
    if (!input_getDirStatsAndRewind(hfuzz)) {
        hfuzz->io.fileCnt = 0U;
        LOG_W("input_getDirStatsAndRewind('%s')", hfuzz->io.inputDir);
        return false;
    }

    return true;
}

bool input_parseDictionary(honggfuzz_t* hfuzz) {
    LOG_I("Parsing dictionary file '%s'", hfuzz->mutate.dictionaryFile);

    FILE* fDict = fopen(hfuzz->mutate.dictionaryFile, "rb");
    if (fDict == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", hfuzz->mutate.dictionaryFile);
        return false;
    }
    defer {
        fclose(fDict);
    };

    char*  lineptr = NULL;
    size_t n       = 0;
    defer {
        free(lineptr);
    };
    for (;;) {
        ssize_t len = getdelim(&lineptr, &n, '\n', fDict);
        if (len == -1) {
            break;
        }
        if (dict_isFull(hfuzz)) {
            LOG_W("Maximum number of dictionary entries '%zu' already loaded. Skipping the rest",
                ARRAYSIZE(hfuzz->mutate.dictionary));
            break;
        }
        if (len > 1 && lineptr[len - 1] == '\n') {
            lineptr[len - 1] = '\0';
            len--;
        }
        if (lineptr[0] == '#') {
            continue;
        }
        if (lineptr[0] == '\n') {
            continue;
        }
        if (lineptr[0] == '\0') {
            continue;
        }

        const char* start = strchr(lineptr, '"');
        char*       end   = strrchr(lineptr, '"');
        if (!start || !end) {
            LOG_W("Malformed dictionary line '%s', skipping", lineptr);
            continue;
        }
        if ((uintptr_t)start == (uintptr_t)end) {
            LOG_W("Malformed dictionary line '%s', skipping", lineptr);
            continue;
        }
        *end = '\0';

        char bufv[1025] = {};
        if (sscanf(&start[1], "%1024c", bufv) != 1) {
            LOG_W("Malformed dictionary line '%s', skipping", lineptr);
            continue;
        }

        LOG_D("Parsing dictionary word: '%s'", bufv);

        len = util_decodeCString(bufv);
        len = HF_MIN((size_t)len, sizeof(hfuzz->mutate.dictionary[0].val));

        if (dict_add(hfuzz, (const uint8_t*)bufv, len)) {
            LOG_D("Dictionary: loaded word: '%s' (len=%zd)", bufv, len);
        }
    }
    LOG_I("Loaded %zu words from the dictionary '%s'", dict_count(hfuzz),
        hfuzz->mutate.dictionaryFile);
    return true;
}

bool input_parseBlacklist(honggfuzz_t* hfuzz) {
    FILE* fBl = fopen(hfuzz->feedback.blocklistFile, "rb");
    if (fBl == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", hfuzz->feedback.blocklistFile);
        return false;
    }
    defer {
        fclose(fBl);
    };

    char* lineptr = NULL;
    /* lineptr can be NULL, but it's fine for free() */
    defer {
        free(lineptr);
    };
    size_t n = 0;
    for (;;) {
        if (getline(&lineptr, &n, fBl) == -1) {
            break;
        }

        if ((hfuzz->feedback.blocklist = util_Realloc(hfuzz->feedback.blocklist,
                 (hfuzz->feedback.blocklistCnt + 1) * sizeof(hfuzz->feedback.blocklist[0]))) ==
            NULL) {
            PLOG_W("realloc failed (sz=%zu)",
                (hfuzz->feedback.blocklistCnt + 1) * sizeof(hfuzz->feedback.blocklist[0]));
            return false;
        }

        hfuzz->feedback.blocklist[hfuzz->feedback.blocklistCnt] = strtoull(lineptr, 0, 16);
        LOG_D("Blacklist: loaded %'" PRIu64 "'",
            hfuzz->feedback.blocklist[hfuzz->feedback.blocklistCnt]);

        /* Verify entries are sorted so we can use interpolation search */
        if (hfuzz->feedback.blocklistCnt >= 1) {
            if (hfuzz->feedback.blocklist[hfuzz->feedback.blocklistCnt - 1] >
                hfuzz->feedback.blocklist[hfuzz->feedback.blocklistCnt]) {
                LOG_F("Blacklist file not sorted. Use 'tools/createStackBlacklist.sh' to sort "
                      "records");
                return false;
            }
        }
        hfuzz->feedback.blocklistCnt += 1;
    }

    if (hfuzz->feedback.blocklistCnt > 0) {
        LOG_I("Loaded %zu stack hash(es) from the blocklist file", hfuzz->feedback.blocklistCnt);
    } else {
        LOG_F("Empty stack hashes blocklist file '%s'", hfuzz->feedback.blocklistFile);
    }
    return true;
}

static void input_generateFileName(dynfile_t* dynfile, const char* dir, char fname[PATH_MAX]) {
    uint64_t crc64f = util_CRC64(dynfile->data, dynfile->size);
    uint64_t crc64r = util_CRC64Rev(dynfile->data, dynfile->size);
    if (dir) {
        snprintf(fname, PATH_MAX, "%s/%016" PRIx64 "%016" PRIx64 ".%08" PRIx32 ".honggfuzz.cov",
            dir, crc64f, crc64r, (uint32_t)dynfile->size);
    } else {
        snprintf(fname, PATH_MAX, "%016" PRIx64 "%016" PRIx64 ".%08" PRIx32 ".honggfuzz.cov",
            crc64f, crc64r, (uint32_t)dynfile->size);
    }
}

bool input_writeCovFile(const char* dir, dynfile_t* dynfile) {
    char fname[PATH_MAX];
    input_generateFileName(dynfile, dir, fname);

    if (files_exists(fname)) {
        LOG_D("File '%s' already exists in the output corpus directory '%s'", fname, dir);
        return true;
    }

    LOG_D("Adding file '%s' to the corpus directory '%s'", fname, dir);

    /* Use atomic write to ensure corpus files appear fully formed for external observers
     * (e.g., Octane's async corpus sync which may read files while fuzzer is running) */
    if (!files_writeBufToFileAtomic(fname, dynfile->data, dynfile->size)) {
        LOG_W("Couldn't write buffer to file '%s' (sz=%zu)", fname, dynfile->size);
        return false;
    }

    return true;
}

/* true if item1 is bigger than item2 */
static bool input_cmpCov(dynfile_t* item1, dynfile_t* item2) {
    for (size_t j = 0; j < ARRAYSIZE(item1->cov); j++) {
        if (item1->cov[j] > item2->cov[j]) {
            return true;
        }
        if (item1->cov[j] < item2->cov[j]) {
            return false;
        }
    }
    /* Both are equal */
    return false;
}

#define TAILQ_FOREACH_HF(var, head, field)                                                         \
    for ((var) = TAILQ_FIRST((head)); (var); (var) = TAILQ_NEXT((var), field))

void input_addDynamicInput(run_t* run) {
    time_t now = time(NULL);
    ATOMIC_SET(run->global->timing.lastCovUpdate, now);

    dynfile_t* dynfile     = (dynfile_t*)util_Calloc(sizeof(dynfile_t));
    dynfile->size          = run->dynfile->size;
    dynfile->timeExecUSecs = util_timeNowUSecs() - run->timeStartedUSecs;
    dynfile->timeAdded     = now;
    dynfile->data          = (uint8_t*)util_AllocCopy(run->dynfile->data, run->dynfile->size);
#ifdef HF_USE_ENTROPY_SCHEDULE
    dynfile->entropy       = power_ComputeEntropy(dynfile->data, dynfile->size);
#endif
    dynfile->complexity    = power_ComputeComplexity(dynfile->data, dynfile->size);
    dynfile->src           = run->dynfile->src;
    dynfile->imported      = run->dynfile->imported;
    dynfile->newEdges      = run->dynfile->newEdges;
    dynfile->depth         = run->dynfile->depth;
    dynfile->stackDepth    = run->dynfile->stackDepth;
    dynfile->pathHash      = run->dynfile->pathHash;
    dynfile->cmpProgress   = run->dynfile->cmpProgress;
    dynfile->rareEdgeCnt   = run->dynfile->rareEdgeCnt;
    dynfile->selectCnt     = 0;
    memcpy(dynfile->cov, run->dynfile->cov, sizeof(dynfile->cov));
    if (run->dynfile->src) {
        ATOMIC_POST_INC(run->dynfile->src->refs);
    }
    dynfile->phase    = fuzz_getState(run->global);
    dynfile->timedout = run->tmOutSignaled;
    input_generateFileName(dynfile, NULL, dynfile->path);

    MX_SCOPED_RWLOCK_WRITE(&run->global->mutex.dynfileq);

    dynfile->idx = ATOMIC_POST_INC(run->global->io.dynfileqId);

    run->global->feedback.maxCov[0] = HF_MAX(run->global->feedback.maxCov[0], dynfile->cov[0]);
    run->global->feedback.maxCov[1] = HF_MAX(run->global->feedback.maxCov[1], dynfile->cov[1]);
    run->global->feedback.maxCov[2] = HF_MAX(run->global->feedback.maxCov[2], dynfile->cov[2]);
    run->global->feedback.maxCov[3] = HF_MAX(run->global->feedback.maxCov[3], dynfile->cov[3]);

    /* Track unique execution paths */
    if (dynfile->pathHash != 0) {
        ATOMIC_POST_INC(run->global->feedback.uniquePaths);
    }

    run->global->io.dynfileqMaxSz = HF_MAX(run->global->io.dynfileqMaxSz, dynfile->size);

    /* Sort it by coverage - put better coverage earlier in the list */
    dynfile_t* iter = NULL;
    TAILQ_FOREACH_HF (iter, &run->global->io.dynfileq, pointers) {
        if (input_cmpCov(dynfile, iter)) {
            TAILQ_INSERT_BEFORE(iter, dynfile, pointers);
            break;
        }
    }
    if (iter == NULL) {
        TAILQ_INSERT_TAIL(&run->global->io.dynfileq, dynfile, pointers);
    }

    ATOMIC_POST_INC(run->global->io.dynfileqCnt);

    if (run->global->socketFuzzer.enabled) {
        /* Don't add coverage data to files in socketFuzzer mode */
        return;
    }

    const char* outDir =
        run->global->io.outputDir ? run->global->io.outputDir : run->global->io.inputDir;
    if (!input_writeCovFile(outDir, dynfile)) {
        LOG_E("Couldn't save the coverage data to '%s'", run->global->io.outputDir);
        ATOMIC_POST_INC(run->global->cnts.fileIOErrors);
    }

    /* No need to add files to the new coverage dir, if it's not the main phase */
    if (fuzz_getState(run->global) != _HF_STATE_DYNAMIC_MAIN) {
        return;
    }

    ATOMIC_POST_INC(run->global->io.newUnitsAdded);

    if (run->global->io.covDirNew && !input_writeCovFile(run->global->io.covDirNew, dynfile)) {
        LOG_E("Couldn't save the new coverage data to '%s'", run->global->io.covDirNew);
    }
}

bool input_inDynamicCorpus(run_t* run, const char* fname, size_t len) {
    MX_SCOPED_RWLOCK_READ(&run->global->mutex.dynfileq);

    dynfile_t* iter = NULL;
    TAILQ_FOREACH_HF (iter, &run->global->io.dynfileq, pointers) {
        if (strncmp(iter->path, fname, PATH_MAX) == 0 && iter->size == len) {
            return true;
        }
    }
    return false;
}

bool input_prepareDynamicInput(run_t* run, bool needs_mangle) {
    if (ATOMIC_GET(run->global->io.dynfileqCnt) == 0) {
        LOG_F("The dynamic file corpus is empty. This shouldn't happen");
    }

    dynfile_t* current_input = NULL;
    bool       is_imported   = false;

    {
        honggfuzz_t* hfuzz = run->global;  /* Cache global pointer */
        MX_SCOPED_RWLOCK_WRITE(&hfuzz->mutex.dynfileq);

        /*
         * Two-phase selection to avoid spinning when all inputs have low energy:
         * Phase 1 (iterations 0-31): Try probabilistic selection as normal
         * Phase 2 (iterations 32+): Track top candidates, select randomly weighted by energy
         *
         * This maintains power scheduling benefits while guaranteeing fast selection
         * with randomness to avoid doom loops.
         */
        unsigned iterations = 0;
        const unsigned phase1Limit = 32;   /* Try probabilistic selection */
        const unsigned phase2Limit = 32;   /* After phase1, scan for top candidates */
        time_t now = time(NULL);

        /* Instrumentation: selection statistics (sampled every 10000 selections) */
        static uint64_t selectionCount = 0;
        static uint64_t phase1HighEnergy = 0;   /* Selected via high energy in phase 1 */
        static uint64_t phase1LowEnergy = 0;    /* Selected via probabilistic skip in phase 1 */
        static uint64_t phase1Repeat = 0;       /* Selected via triesLeft repeat */
        static uint64_t phase2Fallback = 0;     /* Selected via phase 2 fallback */
        static uint64_t totalEnergySum = 0;     /* Sum of selected energies (for avg) */
        static uint64_t totalIterations = 0;    /* Sum of iterations (for avg) */
        static uint64_t maxIterationsSeen = 0;  /* Max iterations in any selection */
        static uint64_t lastLogTime = 0;

        /* Track top candidates for weighted random selection in fallback */
        #define TOP_CANDIDATES 16
        dynfile_t* topCandidates[TOP_CANDIDATES] = {NULL};
        uint64_t   topEnergies[TOP_CANDIDATES]   = {0};

        for (;;) {
            /* Cache the current pointer to avoid repeated global dereferences */
            dynfile_t* cur = hfuzz->io.dynfileqCurrent;
            
            if (unlikely(cur == NULL)) {
                cur = TAILQ_FIRST(&hfuzz->io.dynfileq);
                hfuzz->io.dynfileqCurrent = cur;
            }

            /* Fast path: repeating a high-energy input */
            if (likely(run->triesLeft)) {
                run->triesLeft--;
                ATOMIC_POST_INC(phase1Repeat);
                break;
            }

            run->current = cur;
            /* Prefetch next entry while processing current (hide memory latency) */
            dynfile_t* next = TAILQ_NEXT(cur, pointers);
            __builtin_prefetch(next, 0, 1);  /* Read, low temporal locality */
            hfuzz->io.dynfileqCurrent = next;
            
            /* Track queue wrap-arounds for corpus health monitoring */
            if (unlikely(next == NULL)) {
                ATOMIC_POST_INC(hfuzz->cnts.corpusQueueWraps);
            }

            /* Imported inputs bypass energy calculation - rare */
            if (unlikely(cur->imported)) {
                break;
            }

            iterations++;

            /* Use cached energy, recompute if stale (>60 seconds old) */
            uint64_t energy;
            time_t energyAge = now - cur->energyTime;
            if (likely(cur->energy != 0 && energyAge <= 60)) {
                energy = cur->energy;  /* Fast path: use cached energy */
            } else {
                energy = power_calculateEnergy(run, cur);
                cur->energy = energy;
                cur->energyTime = now;
            }

            /* Lineage bonus: if parent was fertile (produced children), boost siblings */
            dynfile_t* src = cur->src;
            if (unlikely(src != NULL && ATOMIC_GET(src->refs) > 2)) {
                energy = (energy * 5) >> 2; /* 25% bonus (5/4 = 1.25x) via shift */
            }

            /* High energy - repeat this input (common success case) */
            if (likely(energy >= POWER_BASE_ENERGY)) {
                run->triesLeft = energy >> 8;  /* POWER_BASE_ENERGY = 256 = 2^8 */
                if (unlikely(run->triesLeft > 256)) {
                    run->triesLeft = 256;
                }
                ATOMIC_POST_INC(phase1HighEnergy);
                ATOMIC_POST_ADD(totalEnergySum, energy);
                ATOMIC_POST_ADD(totalIterations, iterations);
                if (unlikely(iterations > ATOMIC_GET(maxIterationsSeen))) {
                    ATOMIC_SET(maxIterationsSeen, iterations);
                }
                break;
            }

            /* Phase 2: After phase1Limit iterations, select from top candidates */
            if (unlikely(iterations >= phase1Limit)) {
                /* Track top candidates only in phase 2 (avoid overhead in phase 1) */
                if (energy > topEnergies[TOP_CANDIDATES - 1]) {
                    for (unsigned i = 0; i < TOP_CANDIDATES; i++) {
                        if (energy > topEnergies[i]) {
                            for (unsigned j = TOP_CANDIDATES - 1; j > i; j--) {
                                topCandidates[j] = topCandidates[j - 1];
                                topEnergies[j]   = topEnergies[j - 1];
                            }
                            topCandidates[i] = cur;
                            topEnergies[i]   = energy;
                            break;
                        }
                    }
                }

                if (iterations >= phase1Limit + phase2Limit && topCandidates[0] != NULL) {
                    /* Track phase 2 fallbacks for metrics */
                    uint64_t fallbackCnt = ATOMIC_POST_INC(hfuzz->cnts.diffFuzzPhase2Fallbacks);
                    
                    /* Rate-limited warning: log first occurrence and then every 1000th */
                    if (unlikely(fallbackCnt == 0 || (fallbackCnt % 1000) == 0)) {
                        LOG_W("Phase 2 fallback triggered (iteration %u, count=%zu, top_energy=%zu)",
                              iterations, (size_t)fallbackCnt + 1, (size_t)topEnergies[0]);
                    }
                    
                    /* Weighted random selection from top candidates */
                    uint64_t totalEnergy = 0;
                    unsigned validCount  = 0;
                    for (unsigned i = 0; i < TOP_CANDIDATES && topCandidates[i] != NULL; i++) {
                        totalEnergy += topEnergies[i];
                        validCount++;
                    }

                    if (likely(validCount > 1 && totalEnergy > 0)) {
                        /* Pick randomly weighted by energy */
                        uint64_t pick = util_rnd64() % totalEnergy;
                        uint64_t cumulative = 0;
                        for (unsigned i = 0; i < validCount; i++) {
                            cumulative += topEnergies[i];
                            if (pick < cumulative) {
                                run->current = topCandidates[i];
                                break;
                            }
                        }
                    } else {
                        run->current = topCandidates[0];
                    }
                    ATOMIC_POST_INC(phase2Fallback);
                    ATOMIC_POST_ADD(totalEnergySum, topEnergies[0]);
                    ATOMIC_POST_ADD(totalIterations, iterations);
                    if (unlikely(iterations > ATOMIC_GET(maxIterationsSeen))) {
                        ATOMIC_SET(maxIterationsSeen, iterations);
                    }
                    break;
                }
                /* In phase 2, keep scanning for better candidates without probabilistic rejection */
                continue;
            }

            /* Phase 1: Low energy, probabilistic skipping */
            uint64_t skip_factor = POWER_BASE_ENERGY / energy;
            /* Cap and round to power of 2 for bitmask (1,2,4,8) */
            if (likely(skip_factor >= 8)) {
                skip_factor = 8;  /* 12.5% chance to select */
            } else if (skip_factor >= 4) {
                skip_factor = 4;
            } else if (skip_factor >= 2) {
                skip_factor = 2;
            } else {
                skip_factor = 1;
            }

            /* Use bitmask instead of modulo (skip_factor is power of 2) */
            if (unlikely((util_rnd64() & (skip_factor - 1)) == 0)) {
                ATOMIC_POST_INC(phase1LowEnergy);
                ATOMIC_POST_ADD(totalEnergySum, energy);
                ATOMIC_POST_ADD(totalIterations, iterations);
                if (unlikely(iterations > ATOMIC_GET(maxIterationsSeen))) {
                    ATOMIC_SET(maxIterationsSeen, iterations);
                }
                break;  /* Usually skip_factor=8, so 87.5% chance to continue */
            }
        }
        #undef TOP_CANDIDATES

        /* Instrumentation: log selection stats every 15 seconds
         * Use time-based check as primary trigger (not count-based) to support
         * slow targets like sol_txn_diff that may only do 10-20 exec/sec.
         * The count check (every 1024) is just to avoid calling time() too often. */
        uint64_t count = ATOMIC_POST_INC(selectionCount);
        if ((count & 0x3FF) == 0) {  /* Check time every 1024 selections */
            time_t logNow = time(NULL);
            time_t lastLog = ATOMIC_GET(lastLogTime);
            if (logNow - lastLog >= 15) {
                ATOMIC_SET(lastLogTime, logNow);
                uint64_t repeat = ATOMIC_GET(phase1Repeat);
                uint64_t high = ATOMIC_GET(phase1HighEnergy);
                uint64_t low = ATOMIC_GET(phase1LowEnergy);
                uint64_t p2 = ATOMIC_GET(phase2Fallback);
                uint64_t esum = ATOMIC_GET(totalEnergySum);
                uint64_t total = repeat + high + low + p2;
                if (total > 0) {
                    uint64_t iters = ATOMIC_GET(totalIterations);
                    uint64_t maxIters = ATOMIC_GET(maxIterationsSeen);
                    uint64_t nonRepeat = high + low + p2;
                    
                    /* Fetch decay/energy stats from global counters */
                    uint64_t eMin = ATOMIC_GET(hfuzz->cnts.energyMin);
                    uint64_t eMax = ATOMIC_GET(hfuzz->cnts.energyMax);
                    uint64_t eTotal = ATOMIC_GET(hfuzz->cnts.energySum);
                    uint64_t eCount = ATOMIC_GET(hfuzz->cnts.energyCount);
                    
                    LOG_I("[SCHED-STATS] total=%zu repeat=%.1f%% high=%.1f%% low=%.1f%% phase2=%.1f%% avg_energy=%zu avg_iters=%.1f max_iters=%zu energy_range=[%zu,%zu]",
                          (size_t)total,
                          (double)repeat * 100.0 / total,
                          (double)high * 100.0 / total,
                          (double)low * 100.0 / total,
                          (double)p2 * 100.0 / total,
                          nonRepeat > 0 ? (size_t)(esum / nonRepeat) : 0,
                          nonRepeat > 0 ? (double)iters / nonRepeat : 0.0,
                          (size_t)maxIters,
                          (size_t)eMin, (size_t)eMax);
                    
                    /* Decay-specific stats for validating power scheduling changes */
                    uint64_t noveltyDecay = ATOMIC_GET(hfuzz->cnts.noveltyDecayApplied);
                    uint64_t freshBoost = ATOMIC_GET(hfuzz->cnts.freshInputBoosts);
                    uint64_t stalePenalty = ATOMIC_GET(hfuzz->cnts.staleInputPenalties);
                    uint64_t diminishing = ATOMIC_GET(hfuzz->cnts.diminishingReturnsPenalties);
                    uint64_t depthPenalty = ATOMIC_GET(hfuzz->cnts.depthPenalties);
                    
                    LOG_I("[DECAY-STATS] novelty_decay=%zu fresh_boost=%zu stale_penalty=%zu diminishing=%zu depth_penalty=%zu corpus=%zu global_avg_energy=%zu",
                          (size_t)noveltyDecay,
                          (size_t)freshBoost,
                          (size_t)stalePenalty,
                          (size_t)diminishing,
                          (size_t)depthPenalty,
                          (size_t)ATOMIC_GET(hfuzz->io.dynfileqCnt),
                          eCount > 0 ? (size_t)(eTotal / eCount) : 0);
                    
                    /* Health and performance stats for fuzzer monitoring */
                    uint64_t execTimeSum = ATOMIC_GET(hfuzz->cnts.execTimeSum);
                    uint64_t execTimeMax = ATOMIC_GET(hfuzz->cnts.execTimeMax);
                    uint64_t execTimeSlow = ATOMIC_GET(hfuzz->cnts.execTimeSlowCnt);
                    uint64_t mutWithCov = ATOMIC_GET(hfuzz->cnts.mutationsWithNewCov);
                    uint64_t mutWithoutCov = ATOMIC_GET(hfuzz->cnts.mutationsWithoutNewCov);
                    uint64_t queueWraps = ATOMIC_GET(hfuzz->cnts.corpusQueueWraps);
                    uint32_t maxDepth = ATOMIC_GET(hfuzz->cnts.corpusMaxDepth);
                    
                    /* Calculate mutation hit rate (percentage that found new coverage) */
                    uint64_t mutTotal = mutWithCov + mutWithoutCov;
                    double hitRate = mutTotal > 0 ? ((double)mutWithCov * 100.0 / mutTotal) : 0.0;
                    
                    /* Calculate coverage plateau (seconds since last new coverage) */
                    uint64_t lastCovTime = ATOMIC_GET(hfuzz->timing.lastCovUpdate);
                    uint64_t plateauSecs = lastCovTime > 0 ? (uint64_t)(logNow - (time_t)lastCovTime) : 0;
                    
                    /* Average exec time (sampled count is mutationsCnt >> 8) */
                    uint64_t sampledCount = total >> 8;
                    uint64_t avgExecTime = sampledCount > 0 ? (execTimeSum / sampledCount) : 0;
                    
                    LOG_I("[HEALTH-STATS] exec_avg=%zuus exec_max=%zuus slow_execs=%zu mut_hit_rate=%.2f%% plateau_secs=%zu queue_wraps=%zu max_depth=%u",
                          (size_t)avgExecTime,
                          (size_t)execTimeMax,
                          (size_t)execTimeSlow,
                          hitRate,
                          (size_t)plateauSecs,
                          (size_t)queueWraps,
                          maxDepth);
                    
                    /* Sanity check stats (should all be 0 or very low) */
                    uint64_t forkFails = ATOMIC_GET(hfuzz->cnts.forkFailures);
                    uint64_t persistResets = ATOMIC_GET(hfuzz->cnts.persistentResets);
                    uint64_t ioErrors = ATOMIC_GET(hfuzz->cnts.fileIOErrors);
                    
                    if (forkFails > 0 || persistResets > 0 || ioErrors > 0) {
                        LOG_W("[SANITY-WARN] fork_failures=%zu persistent_resets=%zu io_errors=%zu",
                              (size_t)forkFails, (size_t)persistResets, (size_t)ioErrors);
                    }
                    
                    /* Differential fuzzing specific stats */
                    uint64_t uniqueCrashes = ATOMIC_GET(hfuzz->cnts.uniqueCrashesCnt);
                    uint64_t totalCrashes = ATOMIC_GET(hfuzz->cnts.crashesCnt);
                    uint64_t timeouts = ATOMIC_GET(hfuzz->cnts.timeoutedCnt);
                    uint64_t fertileBoosts = ATOMIC_GET(hfuzz->cnts.diffFuzzFertileBoosts);
                    uint64_t saturatedLineages = ATOMIC_GET(hfuzz->cnts.diffFuzzSaturatedLineages);
                    uint64_t exploreSelects = ATOMIC_GET(hfuzz->cnts.explorationModeSelections);
                    uint64_t lastCrashTime = ATOMIC_GET(hfuzz->cnts.lastCrashTime);
                    
                    /* Time since last crash in human-readable format */
                    uint64_t secsSinceCrash = lastCrashTime > 0 ? (uint64_t)(logNow - (time_t)lastCrashTime) : 0;
                    uint64_t hoursSinceCrash = secsSinceCrash / 3600;
                    uint64_t minsSinceCrash = (secsSinceCrash % 3600) / 60;
                    
                    /* Stagnation in human-readable format */
                    uint64_t stagnationHours = plateauSecs / 3600;
                    uint64_t stagnationMins = (plateauSecs % 3600) / 60;
                    
                    /* Corpus growth rate (inputs added since last log) */
                    size_t currentCorpusSize = ATOMIC_GET(hfuzz->io.dynfileqCnt);
                    size_t lastCorpusSize = ATOMIC_GET(hfuzz->cnts.corpusSizeAtLastLog);
                    size_t corpusGrowth = (currentCorpusSize > lastCorpusSize) ? 
                                          (currentCorpusSize - lastCorpusSize) : 0;
                    ATOMIC_SET(hfuzz->cnts.corpusSizeAtLastLog, currentCorpusSize);
                    
                    LOG_I("[DIFF-FUZZ-STATS] unique_crashes=%zu total_crashes=%zu timeouts=%zu "
                          "fertile_boosts=%zu saturated=%zu explore_selects=%zu "
                          "since_crash=%zuh%zum stagnation=%zuh%zum corpus_growth=%zu",
                          (size_t)uniqueCrashes,
                          (size_t)totalCrashes,
                          (size_t)timeouts,
                          (size_t)fertileBoosts,
                          (size_t)saturatedLineages,
                          (size_t)exploreSelects,
                          (size_t)hoursSinceCrash, (size_t)minsSinceCrash,
                          (size_t)stagnationHours, (size_t)stagnationMins,
                          corpusGrowth);
                    
                    /* Defer the metrics bridge call until after the rwlock is released.
                     * All values are already captured in local variables from ATOMIC_GETs. */
                    run->pendingStatsLog = true;
                    run->statsSnapshot.mutationsCnt        = (uint64_t)ATOMIC_GET(hfuzz->cnts.mutationsCnt);
                    run->statsSnapshot.softCntPc           = (uint64_t)ATOMIC_GET(hfuzz->feedback.hwCnts.softCntPc);
                    run->statsSnapshot.softCntEdge         = (uint64_t)ATOMIC_GET(hfuzz->feedback.hwCnts.softCntEdge);
                    run->statsSnapshot.softCntCmp          = (uint64_t)ATOMIC_GET(hfuzz->feedback.hwCnts.softCntCmp);
                    run->statsSnapshot.softCntEdgeBucket   = (uint64_t)ATOMIC_GET(hfuzz->feedback.hwCnts.softCntEdgeBucket);
                    run->statsSnapshot.total               = (uint64_t)total;
                    run->statsSnapshot.repeatPct           = (float)((double)repeat * 100.0 / total);
                    run->statsSnapshot.highPct             = (float)((double)high * 100.0 / total);
                    run->statsSnapshot.lowPct              = (float)((double)low * 100.0 / total);
                    run->statsSnapshot.phase2Pct           = (float)((double)p2 * 100.0 / total);
                    run->statsSnapshot.avgEnergy           = nonRepeat > 0 ? (uint64_t)(esum / nonRepeat) : 0;
                    run->statsSnapshot.avgIters            = nonRepeat > 0 ? (float)((double)iters / nonRepeat) : 0.0f;
                    run->statsSnapshot.maxIters            = (uint64_t)maxIters;
                    run->statsSnapshot.eMin                = (uint64_t)eMin;
                    run->statsSnapshot.eMax                = (uint64_t)eMax;
                    run->statsSnapshot.noveltyDecay        = (uint64_t)noveltyDecay;
                    run->statsSnapshot.freshBoost          = (uint64_t)freshBoost;
                    run->statsSnapshot.stalePenalty         = (uint64_t)stalePenalty;
                    run->statsSnapshot.diminishing         = (uint64_t)diminishing;
                    run->statsSnapshot.depthPenalty         = (uint64_t)depthPenalty;
                    run->statsSnapshot.corpusSize           = (uint64_t)currentCorpusSize;
                    run->statsSnapshot.globalAvgEnergy     = eCount > 0 ? (uint64_t)(eTotal / eCount) : 0;
                    run->statsSnapshot.avgExecTime         = (uint64_t)avgExecTime;
                    run->statsSnapshot.execTimeMax         = (uint64_t)execTimeMax;
                    run->statsSnapshot.execTimeSlow        = (uint64_t)execTimeSlow;
                    run->statsSnapshot.hitRate             = (float)hitRate;
                    run->statsSnapshot.plateauSecs         = (uint64_t)plateauSecs;
                    run->statsSnapshot.queueWraps          = (uint64_t)queueWraps;
                    run->statsSnapshot.maxDepth            = maxDepth;
                    run->statsSnapshot.uniqueCrashes       = (uint64_t)uniqueCrashes;
                    run->statsSnapshot.totalCrashes        = (uint64_t)totalCrashes;
                    run->statsSnapshot.timeouts            = (uint64_t)timeouts;
                    run->statsSnapshot.fertileBoosts       = (uint64_t)fertileBoosts;
                    run->statsSnapshot.saturatedLineages   = (uint64_t)saturatedLineages;
                    run->statsSnapshot.exploreSelects      = (uint64_t)exploreSelects;
                    run->statsSnapshot.secsSinceCrash      = (uint64_t)secsSinceCrash;
                    run->statsSnapshot.stagnationSecs      = (uint64_t)plateauSecs;
                    run->statsSnapshot.corpusGrowth        = (uint64_t)corpusGrowth;
                }
            }
        }

        current_input = run->current;
        is_imported   = current_input->imported;

        /* Track selection count for diminishing returns */
        if (!is_imported) {
            ATOMIC_POST_INC(current_input->selectCnt);
        }

        if (is_imported) {
            dynfile_t* next = TAILQ_NEXT(current_input, pointers);
            if (run->global->io.dynfileqCurrent == current_input) {
                run->global->io.dynfileqCurrent = next;
            }
            if (run->global->io.dynfileq2Current == current_input) {
                run->global->io.dynfileq2Current = next;
            }
            if (run->global->io.dynfileqDiverseCurrent == current_input) {
                run->global->io.dynfileqDiverseCurrent = next;
            }

            TAILQ_REMOVE(&run->global->io.dynfileq, current_input, pointers);
            if (ATOMIC_GET(run->global->io.dynfileqCnt) > 0) {
                ATOMIC_POST_DEC(run->global->io.dynfileqCnt);
            }
            if (run->global->io.dynfileqCurrent == NULL) {
                run->global->io.dynfileqCurrent = TAILQ_FIRST(&run->global->io.dynfileq);
            }
            if (run->global->io.dynfileq2Current == NULL) {
                run->global->io.dynfileq2Current = TAILQ_FIRST(&run->global->io.dynfileq);
            }
            if (run->global->io.dynfileqDiverseCurrent == NULL) {
                run->global->io.dynfileqDiverseCurrent = TAILQ_FIRST(&run->global->io.dynfileq);
            }

            run->triesLeft = 0;
        }
    }

    /* Flush deferred metrics log AFTER releasing the rwlock to avoid blocking
     * all fuzzer threads on ClickHouse network I/O. */
    if (run->pendingStatsLog) {
        run->pendingStatsLog = false;
        const __typeof__(run->statsSnapshot)* s = &run->statsSnapshot;
        hfuzz_metrics_log_stats(
            s->mutationsCnt, s->softCntPc, s->softCntEdge, s->softCntCmp, s->softCntEdgeBucket,
            s->total, s->repeatPct, s->highPct, s->lowPct, s->phase2Pct,
            s->avgEnergy, s->avgIters, s->maxIters, s->eMin, s->eMax,
            s->noveltyDecay, s->freshBoost, s->stalePenalty, s->diminishing,
            s->depthPenalty, s->corpusSize, s->globalAvgEnergy,
            s->avgExecTime, s->execTimeMax, s->execTimeSlow, s->hitRate,
            s->plateauSecs, s->queueWraps, s->maxDepth,
            s->uniqueCrashes, s->totalCrashes, s->timeouts,
            s->fertileBoosts, s->saturatedLineages, s->exploreSelects,
            s->secsSinceCrash, s->stagnationSecs, s->corpusGrowth
        );
    }

    /* Copy data outside of the lock - inputs are immutable once in the queue */
    input_setSize(run, current_input->size);
    run->dynfile->idx           = current_input->idx;
    run->dynfile->timeExecUSecs = current_input->timeExecUSecs;
    run->dynfile->timeAdded     = is_imported ? 0 : current_input->timeAdded;
    run->dynfile->src           = is_imported ? NULL : current_input;
    run->dynfile->refs          = 0;
    run->dynfile->phase         = fuzz_getState(run->global);
    run->dynfile->timedout      = current_input->timedout;
    run->dynfile->imported      = is_imported;
    run->dynfile->stackDepth    = current_input->stackDepth;
    run->dynfile->pathHash      = current_input->pathHash;
    run->dynfile->cmpProgress   = current_input->cmpProgress;
    run->dynfile->rareEdgeCnt   = current_input->rareEdgeCnt;
#ifdef HF_USE_ENTROPY_SCHEDULE
    run->dynfile->entropy       = current_input->entropy;
#endif
    memcpy(run->dynfile->cov, current_input->cov, sizeof(run->dynfile->cov));
    snprintf(run->dynfile->path, sizeof(run->dynfile->path), "%s", current_input->path);
    memcpy(run->dynfile->data, current_input->data, current_input->size);

    if (is_imported) {
        /* Imported input was removed from list, free it after copying */
        run->current       = NULL;
        run->mutationTiers = 0; /* No mutations applied to imported input */
        free(current_input->data);
        free(current_input);
        return true;
    }

    if (needs_mangle) {
        mangle_mangleContent(run);
    } else {
        run->mutationTiers = 0;
    }

    return true;
}

bool input_dynamicQueueGetNext(char fname[PATH_MAX], DIR* dynamicDirPtr, char* dynamicWorkDir) {
    static pthread_mutex_t input_mutex = PTHREAD_MUTEX_INITIALIZER;
    MX_SCOPED_LOCK(&input_mutex);

    for (;;) {
        errno                = 0;
        struct dirent* entry = readdir(dynamicDirPtr);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir_r('%s')", dynamicWorkDir);
            return false;
        }
        if (entry == NULL) {
            return false;
        }
        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "%s/%s", dynamicWorkDir, entry->d_name);
        struct stat st;
        if (stat(path, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", path);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", path);
            continue;
        }

        snprintf(fname, PATH_MAX, "%s/%s", dynamicWorkDir, entry->d_name);
        return true;
    }
}

void input_enqueueDynamicInputs(honggfuzz_t* hfuzz) {
    char dynamicWorkDir[PATH_MAX];

    snprintf(dynamicWorkDir, sizeof(dynamicWorkDir), "%s", hfuzz->io.dynamicInputDir);

    int dynamicDirFd = TEMP_FAILURE_RETRY(open(dynamicWorkDir, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (dynamicDirFd == -1) {
        PLOG_W("open('%s', O_DIRECTORY|O_RDONLY|O_CLOEXEC)", dynamicWorkDir);
        return;
    }

    DIR* dynamicDirPtr;
    if ((dynamicDirPtr = fdopendir(dynamicDirFd)) == NULL) {
        PLOG_W("fdopendir(dir='%s', fd=%d)", dynamicWorkDir, dynamicDirFd);
        close(dynamicDirFd);
        return;
    }

    char dynamicInputFileName[PATH_MAX];
    for (;;) {
        if (!input_dynamicQueueGetNext(dynamicInputFileName, dynamicDirPtr, dynamicWorkDir)) {
            break;
        }

        int dynamicFileFd;
        if ((dynamicFileFd = open(dynamicInputFileName, O_RDWR)) == -1) {
            PLOG_E("Error opening dynamic input file: %s", dynamicInputFileName);
            continue;
        }

        /* Get file status. */
        struct stat dynamicFileStat;
        size_t      dynamicFileSz;

        if (fstat(dynamicFileFd, &dynamicFileStat) == -1) {
            PLOG_E("Error getting file status: %s", dynamicInputFileName);
            close(dynamicFileFd);
            continue;
        }

        dynamicFileSz = dynamicFileStat.st_size;

        uint8_t* dynamicFile = (uint8_t*)mmap(
            NULL, dynamicFileSz, PROT_READ | PROT_WRITE, MAP_SHARED, dynamicFileFd, 0);

        if (dynamicFile == MAP_FAILED) {
            PLOG_E("Error mapping dynamic input file: %s", dynamicInputFileName);
            close(dynamicFileFd);
            continue;
        }

        LOG_I("Loading dynamic input file: %s (%zu)", dynamicInputFileName, dynamicFileSz);

        run_t tmp_run;
        tmp_run.global        = hfuzz;
        dynfile_t tmp_dynfile = {
            .size          = dynamicFileSz,
            .cov           = {0xff, 0xff, 0xff, 0xff},
            .idx           = 0,
            .fd            = -1,
            .timeExecUSecs = 1,
            .path          = "",
            .timedout      = false,
            .imported      = true,
            .data          = dynamicFile,
        };
        tmp_run.timeStartedUSecs = util_timeNowUSecs() - 1;
        tmp_run.tmOutSignaled    = false;
        memcpy(tmp_dynfile.path, dynamicInputFileName, PATH_MAX);
        tmp_run.dynfile = &tmp_dynfile;
        input_addDynamicInput(&tmp_run);

        /* Unmap input file. */
        if (munmap((void*)dynamicFile, dynamicFileSz) == -1) {
            PLOG_E("Error unmapping input file!");
        }

        /* Close input file. */
        if (close(dynamicFileFd) == -1) {
            PLOG_E("Error closing input file!");
        }

        /* Remove enqueued file from the directory. */
        unlink(dynamicInputFileName);
    }
    closedir(dynamicDirPtr);
}

const uint8_t* input_getRandomInputAsBuf(run_t* run, size_t* len) {
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        LOG_W(
            "The dynamic input queue is empty because no instrumentation mode (-x) was requested");
        *len = 0;
        return NULL;
    }

    if (ATOMIC_GET(run->global->io.dynfileqCnt) == 0) {
        *len = 0;
        return NULL;
    }

    dynfile_t* current = NULL;
    {
        MX_SCOPED_RWLOCK_WRITE(&run->global->mutex.dynfileq);

        if (run->global->io.dynfileq2Current == NULL) {
            run->global->io.dynfileq2Current = TAILQ_FIRST(&run->global->io.dynfileq);
        }

        current                          = run->global->io.dynfileq2Current;
        run->global->io.dynfileq2Current = TAILQ_NEXT(run->global->io.dynfileq2Current, pointers);
    }

    *len = current->size;
    return current->data;
}

/*
 * Select an input diverse from the current one for crossover.
 * Diversity = different lineage + different coverage profile.
 */
const uint8_t* input_getDiverseInputAsBuf(run_t* run, size_t* len) {
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        *len = 0;
        return NULL;
    }

    if (ATOMIC_GET(run->global->io.dynfileqCnt) == 0) {
        *len = 0;
        return NULL;
    }

    dynfile_t* current_src = run->dynfile->src;
    uint64_t   current_cov = run->dynfile->cov[0];
    dynfile_t* best        = NULL;
    uint64_t   best_diff   = 0;

    MX_SCOPED_RWLOCK_WRITE(&run->global->mutex.dynfileq);

    dynfile_t* iter = run->global->io.dynfileqDiverseCurrent;
    if (iter == NULL) {
        iter = TAILQ_FIRST(&run->global->io.dynfileq);
    }
    if (iter == NULL) {
        *len = 0;
        return NULL;
    }

    const size_t windowSize = 16;
    for (size_t i = 0; i < windowSize; i++) {
        if (iter == NULL) {
            iter = TAILQ_FIRST(&run->global->io.dynfileq);
            if (iter == NULL) break;
        }

        uint64_t cov_diff = (iter->cov[0] > current_cov) ? (iter->cov[0] - current_cov)
                                                         : (current_cov - iter->cov[0]);

        if (iter->src != current_src && iter->src != run->current) {
            cov_diff += (current_cov / 4);
        }

        if (cov_diff > best_diff) {
            best_diff = cov_diff;
            best      = iter;
        }

        iter = TAILQ_NEXT(iter, pointers);
    }

    run->global->io.dynfileqDiverseCurrent = iter;

    if (best == NULL) {
        best = TAILQ_FIRST(&run->global->io.dynfileq);
    }

    if (best == NULL) {
        *len = 0;
        return NULL;
    }

    *len = best->size;
    return best->data;
}

static bool input_shouldReadNewFile(run_t* run) {
    if (fuzz_getState(run->global) != _HF_STATE_DYNAMIC_DRY_RUN) {
        input_setSize(run, run->global->mutate.maxInputSz);
        return true;
    }

    if (!run->staticFileTryMore) {
        run->staticFileTryMore = true;
        /* Start with 4 bytes, increase the size in following iterations */
        input_setSize(run, HF_MIN(4U, run->global->mutate.maxInputSz));
        return true;
    }

    /* Increase size of the current file by a factor of 2, and return it instead of a new file */
    size_t newsz = run->dynfile->size * 2;
    if (newsz >= run->global->mutate.maxInputSz) {
        /* That's the largest size for this specific file that will be ever used */
        newsz                  = run->global->mutate.maxInputSz;
        run->staticFileTryMore = false;
    }

    input_setSize(run, newsz);
    return false;
}

bool input_prepareStaticFile(run_t* run, bool rewind, bool needs_mangle) {
    if (input_shouldReadNewFile(run)) {
        for (;;) {
            size_t flen;
            if (!input_getNext(run, run->dynfile->path, &flen, /* rewind= */ rewind)) {
                return false;
            }
            if (needs_mangle) {
                break;
            }
            if (!input_inDynamicCorpus(run, run->dynfile->path, HF_MIN(flen, run->dynfile->size))) {
                break;
            }
            LOG_D("Skipping '%s' (dynamic corpus size=%zu, file size=%zu) as it's already in the "
                  "dynamic corpus",
                run->dynfile->path, run->dynfile->size, flen);
        }
        run->global->io.testedFileCnt++;
    }

    LOG_D("Reading '%s' (max size=%zu)", run->dynfile->path, run->dynfile->size);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", run->global->io.inputDir, run->dynfile->path);

    ssize_t fileSz = files_readFileToBufMax(path, run->dynfile->data, run->dynfile->size);
    if (fileSz < 0) {
        LOG_E("Couldn't read contents of '%s'", path);
        return false;
    }

    if (run->staticFileTryMore && ((size_t)fileSz < run->dynfile->size)) {
        /* The file is smaller than the requested size, no need to re-read it anymore */
        run->staticFileTryMore = false;
    }

    input_setSize(run, fileSz);
    util_memsetInline(run->dynfile->cov, '\0', sizeof(run->dynfile->cov));
    run->dynfile->idx       = 0;
    run->dynfile->src       = NULL;
    run->dynfile->refs      = 0;
    run->dynfile->phase     = fuzz_getState(run->global);
    run->dynfile->timedout  = false;
    run->dynfile->timeAdded = time(NULL);
    run->dynfile->newEdges  = 0;
    run->dynfile->depth     = 0;
#ifdef HF_USE_ENTROPY_SCHEDULE
    run->dynfile->entropy   = power_ComputeEntropy(run->dynfile->data, run->dynfile->size);
#endif
    run->dynfile->complexity = power_ComputeComplexity(run->dynfile->data, run->dynfile->size);

    if (needs_mangle) {
        mangle_mangleContent(run);
    } else {
        run->mutationTiers = 0;
    }

    return true;
}

bool input_removeStaticFile(const char* dir, const char* name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (unlink(path) == -1 && errno != EEXIST) {
        PLOG_E("unlink('%s') failed", path);
        return false;
    }
    return true;
}

bool input_prepareExternalFile(run_t* run) {
    snprintf(run->dynfile->path, sizeof(run->dynfile->path), "[EXTERNAL]");

    int fd = files_writeBufToTmpFile(run->global->io.workDir, (const uint8_t*)"", 0, 0);
    if (fd == -1) {
        LOG_E("Couldn't write input file to a temporary buffer");
        return false;
    }
    defer {
        close(fd);
    };

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/dev/fd/%d", fd);

    const char* const argv[] = {run->global->exe.externalCommand, fname, NULL};
    if (subproc_System(run, argv) != 0) {
        LOG_E("Subprocess '%s' returned abnormally", run->global->exe.externalCommand);
        return false;
    }
    LOG_D("Subporcess '%s' finished with success", run->global->exe.externalCommand);

    input_setSize(run, run->global->mutate.maxInputSz);
    ssize_t sz = files_readFromFdSeek(fd, run->dynfile->data, run->global->mutate.maxInputSz, 0);
    if (sz == -1) {
        LOG_E("Couldn't read file from fd=%d", fd);
        return false;
    }

    input_setSize(run, (size_t)sz);
    return true;
}

bool input_postProcessFile(run_t* run, const char* cmd) {
    int fd =
        files_writeBufToTmpFile(run->global->io.workDir, run->dynfile->data, run->dynfile->size, 0);
    if (fd == -1) {
        LOG_E("Couldn't write input file to a temporary buffer");
        return false;
    }
    defer {
        close(fd);
    };

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/dev/fd/%d", fd);

    const char* const argv[] = {cmd, fname, NULL};
    if (subproc_System(run, argv) != 0) {
        LOG_E("Subprocess '%s' returned abnormally", cmd);
        return false;
    }
    LOG_D("Subporcess '%s' finished with success", cmd);

    input_setSize(run, run->global->mutate.maxInputSz);
    ssize_t sz = files_readFromFdSeek(fd, run->dynfile->data, run->global->mutate.maxInputSz, 0);
    if (sz == -1) {
        LOG_E("Couldn't read file from fd=%d", fd);
        return false;
    }

    input_setSize(run, (size_t)sz);

    return true;
}
