/*
 *
 * honggfuzz - fuzzing routines
 * -----------------------------------------
 *
 * Authors: Robert Swiecki <swiecki@google.com>
 *          Felix Gröbert <groebert@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
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

#include "fuzz.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "honggfuzz.h"
#include "input.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "report.h"
#include "sanitizers.h"
#include "socketfuzzer.h"
#include "subproc.h"
#include "hfuzz_metrics.h"

static time_t termTimeStamp = 0;

bool fuzz_isTerminating(void) {
    if (ATOMIC_GET(termTimeStamp) != 0) {
        return true;
    }
    return false;
}

void fuzz_setTerminating(void) {
    if (ATOMIC_GET(termTimeStamp) != 0) {
        return;
    }
    ATOMIC_SET(termTimeStamp, time(NULL));
}

bool fuzz_shouldTerminate() {
    if (ATOMIC_GET(termTimeStamp) == 0) {
        return false;
    }
    if ((time(NULL) - ATOMIC_GET(termTimeStamp)) > 5) {
        return true;
    }
    return false;
}

fuzzState_t fuzz_getState(honggfuzz_t* hfuzz) {
    return ATOMIC_GET(hfuzz->feedback.state);
}

static void fuzz_setDynamicMainState(run_t* run) {
    /* All threads need to indicate willingness to switch to the DYNAMIC_MAIN state. Count them! */
    static uint32_t cnt = 0;
    ATOMIC_PRE_INC(cnt);

    MX_SCOPED_LOCK(&run->global->mutex.state);

    if (fuzz_getState(run->global) != _HF_STATE_DYNAMIC_DRY_RUN) {
        /* Already switched out of the Dry Run */
        return;
    }

    LOG_I("Entering phase 2/3: Switching to the Feedback Driven Mode");
    ATOMIC_SET(run->global->cfg.switchingToFDM, true);

    for (;;) {
        /* Check if all threads have already reported in for changing state */
        if (ATOMIC_GET(cnt) == run->global->threads.threadsMax) {
            break;
        }
        if (fuzz_isTerminating()) {
            return;
        }
        util_sleepForMSec(10); /* Check every 10ms */
    }

    ATOMIC_SET(run->global->cfg.switchingToFDM, false);

    if (run->global->cfg.minimize) {
        LOG_I("Entering phase 3/3: Corpus Minimization");
        ATOMIC_SET(run->global->feedback.state, _HF_STATE_DYNAMIC_MINIMIZE);
        fprintf(stderr, "[hfuzz_stats] state=minimize\n");
        return;
    }

    if (run->global->cfg.replay) {
        LOG_I("Replay complete: all corpus files processed");
        fuzz_setTerminating();
        return;
    }

    /*
     * If the initial fuzzing yielded no useful coverage, just add a single empty file to the
     * dynamic corpus, so the dynamic phase doesn't fail because of lack of useful inputs
     */
    if (run->global->io.dynfileqCnt == 0) {
        dynfile_t dynfile = {
            .size          = 0,
            .cov           = {},
            .idx           = 0,
            .fd            = -1,
            .timeExecUSecs = 1,
            .path          = "[DYNAMIC-0-SIZE]",
            .timedout      = false,
            .imported      = false,
            .data          = (uint8_t*)"",
        };
        dynfile_t* tmp_dynfile = run->dynfile;
        run->dynfile           = &dynfile;
        /* Synthesised here, not imported.  Set explicitly because the flag lives on
         * `run` and would otherwise carry over from a previous iteration. */
        run->dynfileFromImport = false;
        input_addDynamicInput(run);
        run->dynfile = tmp_dynfile;
    }
    snprintf(run->dynfile->path, sizeof(run->dynfile->path), "[DYNAMIC]");

    if (run->global->io.maxFileSz == 0 && run->global->mutate.maxInputSz > _HF_INPUT_DEFAULT_SIZE) {
        size_t newsz = (run->global->io.dynfileqMaxSz >= _HF_INPUT_DEFAULT_SIZE)
                           ? run->global->io.dynfileqMaxSz
                           : _HF_INPUT_DEFAULT_SIZE;
        newsz        = (newsz + newsz / 4); /* Add 25% overhead for growth */
        if (newsz > run->global->mutate.maxInputSz) {
            newsz = run->global->mutate.maxInputSz;
        }
        LOG_I("Setting maximum input size to %zu bytes (previously %zu bytes)", newsz,
            run->global->mutate.maxInputSz);
        run->global->mutate.maxInputSz = newsz;
    }

    LOG_I("Entering phase 3/3: Dynamic Main (Feedback Driven Mode)");
    ATOMIC_SET(run->global->feedback.state, _HF_STATE_DYNAMIC_MAIN);

    uint64_t execs = ATOMIC_GET(run->global->cnts.mutationsCnt);
    uint64_t pcs   = ATOMIC_GET(run->global->feedback.hwCnts.softCntPc);
    uint64_t edges = ATOMIC_GET(run->global->feedback.hwCnts.softCntEdge);
    uint64_t corpus = ATOMIC_GET(run->global->io.dynfileqCnt);
    uint64_t uniqueCrashes = ATOMIC_GET(run->global->cnts.uniqueCrashesCnt);
    uint64_t crashes = ATOMIC_GET(run->global->cnts.crashesCnt);
    fprintf(stderr, "[hfuzz_stats] state=dynamic execs=%zu pcs=%zu edges=%zu "
            "corpus=%zu crashes=%zu/%zu threads=%zu\n",
            (size_t)execs, (size_t)pcs, (size_t)edges,
            (size_t)corpus, (size_t)uniqueCrashes, (size_t)crashes,
            (size_t)run->global->threads.threadsMax);
}

static void fuzz_minimizeRemoveFiles(run_t* run) {
    if (run->global->io.outputDir) {
        LOG_I("Minimized files were copied to '%s'", run->global->io.outputDir);
        return;
    }
    if (!input_getDirStatsAndRewind(run->global)) {
        return;
    }
    for (;;) {
        char   fname[PATH_MAX];
        size_t len;
        if (!input_getNext(run, fname, &len, /* rewind= */ false)) {
            break;
        }
        if (!input_inDynamicCorpus(run, fname, len)) {
            if (input_removeStaticFile(run->global->io.inputDir, fname)) {
                LOG_I("Removed unnecessary '%s'", fname);
            }
        }
    }
    LOG_I("Corpus minimization done");
}

static void fuzz_perfFeedback(run_t* run) {
    if (run->global->feedback.skipFeedbackOnTimeout && run->tmOutSignaled) {
        return;
    }
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        return;
    }

    MX_SCOPED_LOCK(&run->global->mutex.feedback);
    defer {
        wmb();
    };

    uint64_t softNewPC         = 0;
    uint64_t softCurPC         = 0;
    uint64_t softNewEdge       = 0;
    uint64_t softCurEdge       = 0;
    uint64_t softNewCmp        = 0;
    uint64_t softCurCmp        = 0;
    uint64_t softEdgeBucketInc = 0;
    bool     softNewStackDepth = false;

    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_SOFT) {
        softNewPC = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidNewPC[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidNewPC[run->fuzzNo].val);
        softCurPC = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidTotalPC[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidTotalPC[run->fuzzNo].val);

        softNewEdge = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidNewEdge[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidNewEdge[run->fuzzNo].val);
        softCurEdge =
            ATOMIC_GET(run->global->feedback.covFeedbackMap->pidTotalEdge[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidTotalEdge[run->fuzzNo].val);

        softNewCmp = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidNewCmp[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidNewCmp[run->fuzzNo].val);
        softCurCmp = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidTotalCmp[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidTotalCmp[run->fuzzNo].val);

        softEdgeBucketInc = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidEdgeBucketInc[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidEdgeBucketInc[run->fuzzNo].val);

        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidLastStackDepth[run->fuzzNo].val);

        softNewStackDepth = ATOMIC_XCHG(
            run->global->feedback.covFeedbackMap->pidNewStackDepth[run->fuzzNo].val, false);
    }

    rmb();

    int64_t diff0 = (int64_t)run->global->feedback.hwCnts.cpuInstrCnt - run->hwCnts.cpuInstrCnt;
    int64_t diff1 = (int64_t)run->global->feedback.hwCnts.cpuBranchCnt - run->hwCnts.cpuBranchCnt;

    /* Any increase in coverage (edge, pc, cmp, hw, stack, edge-bucket) counters forces adding
     * input to the corpus */
    if (run->hwCnts.newBBCnt > 0 || softNewPC > 0 || softNewEdge > 0 || softNewCmp > 0 ||
        softEdgeBucketInc > 0 || softNewStackDepth || diff0 < 0 || diff1 < 0) {
        if (diff0 < 0) {
            run->global->feedback.hwCnts.cpuInstrCnt = run->hwCnts.cpuInstrCnt;
        }
        if (diff1 < 0) {
            run->global->feedback.hwCnts.cpuBranchCnt = run->hwCnts.cpuBranchCnt;
        }
        run->global->feedback.hwCnts.bbCnt += run->hwCnts.newBBCnt;
        run->global->feedback.hwCnts.softCntPc += softNewPC;
        run->global->feedback.hwCnts.softCntEdge += softNewEdge;
        run->global->feedback.hwCnts.softCntCmp += softNewCmp;
        run->global->feedback.hwCnts.softCntEdgeBucket += softEdgeBucketInc;

        LOG_I("Sz:%zu Tm:%" _HF_NONMON_SEP PRIu64 "us (i/b/h/e/p/c/eb) New:%" PRIu64 "/%" PRIu64
              "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
              ", Cur:%" PRIu64 "/%" PRIu64
              "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64,
            run->dynfile->size, util_timeNowUSecs() - run->timeStartedUSecs,
            run->hwCnts.cpuInstrCnt, run->hwCnts.cpuBranchCnt, run->hwCnts.newBBCnt, softNewEdge,
            softNewPC, softNewCmp, softEdgeBucketInc, run->hwCnts.cpuInstrCnt, run->hwCnts.cpuBranchCnt,
            run->global->feedback.hwCnts.bbCnt, run->global->feedback.hwCnts.softCntEdge,
            run->global->feedback.hwCnts.softCntPc, run->global->feedback.hwCnts.softCntCmp,
            run->global->feedback.hwCnts.softCntEdgeBucket);

        if (run->global->io.statsFileName) {
            const time_t curr_sec      = time(NULL);
            const time_t elapsed_sec   = curr_sec - run->global->timing.timeStart;
            size_t       curr_exec_cnt = ATOMIC_GET(run->global->cnts.mutationsCnt);
            /*
             * We increase the mutation counter unconditionally in threads, but if it's
             * above hfuzz->mutationsMax we don't really execute the fuzzing loop.
             * Therefore at the end of fuzzing, the mutation counter might be higher
             * than hfuzz->mutationsMax
             */
            if (run->global->mutate.mutationsMax > 0 &&
                curr_exec_cnt > run->global->mutate.mutationsMax) {
                curr_exec_cnt = run->global->mutate.mutationsMax;
            }
            size_t tot_exec_per_sec = elapsed_sec ? (curr_exec_cnt / elapsed_sec) : 0;

            dprintf(run->global->io.statsFileFd,
                "%lu, %lu, %zu, %zu, %zu, %zu, %zu, %" PRIu64 ", %" PRIu64 ", %zu\n",
                (unsigned long)curr_sec,                          /* unix_time */
                (unsigned long)run->global->timing.lastCovUpdate, /* last_cov_update */
                curr_exec_cnt,                                    /* total_exec */
                tot_exec_per_sec,                                 /* exec_per_sec */
                run->global->cnts.crashesCnt,                     /* crashes */
                run->global->cnts.uniqueCrashesCnt,               /* unique_crashes */
                run->global->cnts.timeoutedCnt,                   /* hangs */
                run->global->feedback.hwCnts.softCntEdge,         /* edge_cov */
                run->global->feedback.hwCnts.softCntPc,           /* block_cov */
                run->global->io.dynfileqCnt                       /* corpus_count */
            );
        }

        /* Update per-input coverage metrics */
        run->dynfile->cov[0] = softCurEdge + softCurPC + run->hwCnts.bbCnt;
        run->dynfile->cov[1] = softCurCmp;
        run->dynfile->cov[2] = run->hwCnts.cpuInstrCnt + run->hwCnts.cpuBranchCnt;
        run->dynfile->cov[3] = run->dynfile->size ? (64 - util_Log2(run->dynfile->size)) : 64;

        /* Track novelty - how many new edges this input discovered */
        run->dynfile->newEdges = (uint32_t)(softNewEdge + softNewPC + run->hwCnts.newBBCnt);

        /* Track mutation depth */
        run->dynfile->depth = run->dynfile->src ? run->dynfile->src->depth + 1 : 0;
        run->dynfile->stackDepth =
            ATOMIC_GET(run->global->feedback.covFeedbackMap->pidLastStackDepth[run->fuzzNo].val);

        /* Track execution path hash for diversity */
        run->dynfile->pathHash =
            ATOMIC_GET(run->global->feedback.covFeedbackMap->pidPathHash[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidPathHash[run->fuzzNo].val);

        /* Track CMP progress for inputs making headway on comparisons */
        run->dynfile->cmpProgress = (uint32_t)ATOMIC_GET(
            run->global->feedback.covFeedbackMap->pidCmpProgress[run->fuzzNo].val);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidCmpProgress[run->fuzzNo].val);

        /* Track rare edges - edges hit by few corpus entries */
        run->dynfile->rareEdgeCnt = (uint16_t)HF_MIN(
            ATOMIC_GET(run->global->feedback.covFeedbackMap->pidRareEdgeCnt[run->fuzzNo].val),
            UINT16_MAX);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidRareEdgeCnt[run->fuzzNo].val);

        /* Credit mutation tiers that led to this coverage gain */
        for (int tier = 0; tier < 4; tier++) {
            if (run->mutationTiers & (1 << tier)) {
                ATOMIC_POST_INC(run->global->mutate.stats[tier].successes);
            }
        }
        ATOMIC_POST_INC(run->global->cnts.mutationsWithNewCov);

        /* In persistent mode with custom mutator, the child may produce output
           of a different size than the original corpus entry.  Use the actual
           post-mutation size so we don't save stale trailing bytes. */
        if (run->global->feedback.covFeedbackMap) {
            size_t post_len = ATOMIC_GET(
                run->global->feedback.covFeedbackMap->postMutInputLen[run->fuzzNo].val);
            if (post_len > 0 && post_len <= (size_t)run->global->mutate.maxInputSz) {
                input_setSize(run, post_len);
            }
        }

        /* Push useful imported input to dynamic queue again for the further mutations.
         * Clearing the flag is what makes the re-queued entry mutable, so it has to
         * happen -- but it is also the only record that this input came from another
         * host rather than from us, and covDirNew must not re-export it.  Carry that
         * one bit across the clear. */
        run->dynfileFromImport = run->dynfile->imported;
        if (run->dynfile->imported) {
            LOG_I("File imported: %s", run->dynfile->path);
            run->dynfile->imported = false;
        }
        input_addDynamicInput(run);

        if (run->global->socketFuzzer.enabled) {
            LOG_D("SocketFuzzer: fuzz: new BB (perf)");
            fuzz_notifySocketFuzzerNewCov(run->global);
        }

        /* Log coverage metrics (optional - weak symbol, no-op if not overridden) */
        hfuzz_metrics_log_coverage(
            softNewPC,
            softNewEdge,
            softNewCmp,
            run->global->feedback.hwCnts.softCntPc,
            run->global->feedback.hwCnts.softCntEdge,
            run->global->feedback.hwCnts.softCntCmp,
            run->global->io.dynfileqCnt);

        /* Log detailed coverage map for source-level analysis */
        uint64_t total_guards = atomic_load_explicit(&run->global->feedback.covFeedbackMap->guardNb, memory_order_relaxed);
        hfuzz_metrics_log_detailed_coverage(
            run->global->feedback.covFeedbackMap->pcGuardMap,
            total_guards);
    } else {
        ATOMIC_POST_INC(run->global->cnts.mutationsWithoutNewCov);
        if (run->dynfile->imported) {
            /* Remove useless imported inputs from corpus */
            LOG_D("Removing useless imported file: %s", run->dynfile->path);
            char fname[PATH_MAX];
            snprintf(fname, PATH_MAX, "%s/%s",
                run->global->io.outputDir ? run->global->io.outputDir : run->global->io.inputDir,
                run->dynfile->path);
            unlink(fname);
        }
    }
}

/* Return value indicates whether report file should be updated with the current verified crash */
static bool fuzz_runVerifier(run_t* run) {
    if (!run->crashFileName[0] || !run->backtrace) {
        return false;
    }

    uint64_t backtrace = run->backtrace;

    char origCrashPath[PATH_MAX];
    snprintf(origCrashPath, sizeof(origCrashPath), "%s", run->crashFileName);
    /* Workspace is inherited, just append a extra suffix */
    char verFile[PATH_MAX];
    snprintf(verFile, sizeof(verFile), "%s.verified", origCrashPath);

    if (files_exists(verFile)) {
        LOG_D("Crash file to verify '%s' is already verified as '%s'", origCrashPath, verFile);
        return false;
    }

    for (int i = 0; i < _HF_VERIFIER_ITER; i++) {
        LOG_I("Launching verifier for HASH: %" PRIx64 " (iteration: %d out of %d)", run->backtrace,
            i + 1, _HF_VERIFIER_ITER);
        run->timeStartedUSecs = util_timeNowUSecs();
        run->backtrace        = 0;
        run->access           = 0;
        run->exception        = 0;
        run->mainWorker       = false;

        if (!subproc_Run(run)) {
            LOG_F("subproc_Run()");
        }

        /* If stack hash doesn't match skip name tag and exit */
        if (run->backtrace != backtrace) {
            LOG_E("Verifier stack mismatch: (original) %" PRIx64 " != (new) %" PRIx64, backtrace,
                run->backtrace);
            run->backtrace = backtrace;
            return true;
        }

        LOG_I("Verifier for HASH: %" PRIx64 " (iteration: %d, left: %d). MATCH!", run->backtrace,
            i + 1, _HF_VERIFIER_ITER - i - 1);
    }

    /* Copy file with new suffix & remove original copy */
    int fd = TEMP_FAILURE_RETRY(open(verFile, O_CREAT | O_EXCL | O_WRONLY, 0600));
    if (fd == -1 && errno == EEXIST) {
        LOG_I("It seems that '%s' already exists, skipping", verFile);
        return false;
    }
    if (fd == -1) {
        PLOG_E("Couldn't create '%s'", verFile);
        return true;
    }
    defer {
        close(fd);
    };
    size_t ver_size = run->dynfile->size;
    if (run->global->feedback.covFeedbackMap) {
        size_t post_len = ATOMIC_GET(
            run->global->feedback.covFeedbackMap->postMutInputLen[run->fuzzNo].val);
        if (post_len > 0 && post_len <= (size_t)run->global->mutate.maxInputSz) {
            ver_size = post_len;
        }
    }
    if (!files_writeToFd(fd, run->dynfile->data, ver_size)) {
        LOG_E("Couldn't save verified file as '%s'", verFile);
        unlink(verFile);
        return true;
    }

    LOG_I("Verified crash for HASH: %" PRIx64 " and saved it as '%s'", backtrace, verFile);
    ATOMIC_PRE_INC(run->global->cnts.verifiedCrashesCnt);

    return true;
}

static bool fuzz_fetchInput(run_t* run) {
    /* Periodic stats flush for non-dynamic states (dry run, static, minimize).
     * Once in DYNAMIC_MAIN, input_prepareDynamicInput handles stats with
     * full sched/decay/health counters -- so we stop here to avoid
     * overwriting those with zeroes. */
    {
        static time_t lastStatsTime = 0;
        time_t now = time(NULL);
        time_t last = __atomic_load_n(&lastStatsTime, __ATOMIC_SEQ_CST);
        if (now - last >= 150
            && fuzz_getState(run->global) != _HF_STATE_DYNAMIC_MAIN
            && __atomic_compare_exchange_n(
                &lastStatsTime, &last, now, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            honggfuzz_t* hfuzz = run->global;
            uint64_t execs = ATOMIC_GET(hfuzz->cnts.mutationsCnt);
            uint64_t pcs   = ATOMIC_GET(hfuzz->feedback.hwCnts.softCntPc);
            uint64_t edges = ATOMIC_GET(hfuzz->feedback.hwCnts.softCntEdge);
            uint64_t corpus = ATOMIC_GET(hfuzz->io.dynfileqCnt);
            uint64_t crashes = ATOMIC_GET(hfuzz->cnts.crashesCnt);
            uint64_t uniqueCrashes = ATOMIC_GET(hfuzz->cnts.uniqueCrashesCnt);
            fuzzState_t st = fuzz_getState(hfuzz);
            const char* state_str = (st == _HF_STATE_DYNAMIC_DRY_RUN) ? "dry_run"
                                  : (st == _HF_STATE_DYNAMIC_MAIN)    ? "dynamic"
                                  : (st == _HF_STATE_DYNAMIC_MINIMIZE) ? "minimize"
                                  : (st == _HF_STATE_REPLAY)           ? "replay"
                                  :                                      "static";

            uint64_t timeouts = ATOMIC_GET(hfuzz->cnts.timeoutedCnt);
            uint64_t execTimeSum = ATOMIC_GET(hfuzz->cnts.execTimeSum);
            uint64_t execTimeMax = ATOMIC_GET(hfuzz->cnts.execTimeMax);
            uint64_t execTimeSlow = ATOMIC_GET(hfuzz->cnts.execTimeSlowCnt);
            uint64_t queueWraps = ATOMIC_GET(hfuzz->cnts.corpusQueueWraps);
            uint32_t maxDepth = ATOMIC_GET(hfuzz->cnts.corpusMaxDepth);
            uint64_t lastCovTime = ATOMIC_GET(hfuzz->timing.lastCovUpdate);
            uint64_t plateauSecs = lastCovTime > 0 ? (uint64_t)(now - (time_t)lastCovTime) : 0;
            uint64_t sampledCount = execs >> 8;
            uint64_t avgExecTime = sampledCount > 0 ? (execTimeSum / sampledCount) : 0;

            uint64_t testedFiles = ATOMIC_GET(hfuzz->io.testedFileCnt);
            uint64_t totalFiles = hfuzz->io.fileCnt;
            float dryRunPct = totalFiles > 0 ? (float)testedFiles * 100.0f / (float)totalFiles : 0.0f;

            fprintf(stderr, "[hfuzz_stats] state=%s execs=%zu pcs=%zu edges=%zu "
                    "corpus=%zu crashes=%zu/%zu threads=%zu",
                    state_str, (size_t)execs, (size_t)pcs, (size_t)edges,
                    (size_t)corpus, (size_t)uniqueCrashes, (size_t)crashes,
                    (size_t)hfuzz->threads.threadsMax);
            if (st == _HF_STATE_DYNAMIC_DRY_RUN) {
                fprintf(stderr, " dry_run_progress=%zu/%zu (%.1f%%)",
                        (size_t)testedFiles, (size_t)totalFiles, (double)dryRunPct);
            }
            fprintf(stderr, "\n");

            if (execs > 0) {
                uint64_t truncatedTooLarge = ATOMIC_GET(hfuzz->cnts.inputsTruncatedTooLarge);
                hfuzz_mutation_counters_t mc = {0};
                if (hfuzz->feedback.covFeedbackMap) {
                    feedback_t* cov2 = hfuzz->feedback.covFeedbackMap;
                    for (size_t i = 0; i < hfuzz->threads.threadsMax; i++) {
                        truncatedTooLarge += ATOMIC_GET(cov2->pidInputsTruncatedCnt[i].val);
                        mc.proto_parse_calls      += ATOMIC_GET(cov2->pidProtoParseCallsCnt[i].val);
                        mc.proto_parse_successes  += ATOMIC_GET(cov2->pidProtoParseSuccessesCnt[i].val);
                        mc.custom_mutator_calls   += ATOMIC_GET(cov2->pidCustomMutatorCallsCnt[i].val);
                        mc.custom_mutator_successes += ATOMIC_GET(cov2->pidCustomMutatorSuccessesCnt[i].val);
                        mc.kutator_mutate_cnt         += ATOMIC_GET(cov2->pidKutatorMutateCnt[i].val);
                        mc.kutator_crossover_cnt      += ATOMIC_GET(cov2->pidKutatorCrossOverCnt[i].val);
                        mc.kutator_parse_success_cnt  += ATOMIC_GET(cov2->pidKutatorParseSuccessCnt[i].val);
                        mc.kutator_parse_fail_cnt     += ATOMIC_GET(cov2->pidKutatorParseFailCnt[i].val);
                        mc.encode_overflow_cnt    += ATOMIC_GET(cov2->pidKutatorEncodeOverflow[i].val);
                        mc.no_candidates_cnt      += ATOMIC_GET(cov2->pidKutatorNoCandidates[i].val);
                        mc.exec_fail_cnt          += ATOMIC_GET(cov2->pidExecFailCnt[i].val);
                        mc.verify_cnt             += ATOMIC_GET(cov2->pidVerifyCnt[i].val);
                        mc.harness_reject_cnt     += ATOMIC_GET(cov2->pidHarnessRejectCnt[i].val);
                    }
                    mc.proto_round_cnt  = ATOMIC_GET(hfuzz->mutate.protoRoundCnt);
                    mc.proto_scan_ok_cnt = ATOMIC_GET(hfuzz->mutate.protoScanOkCnt);
                    mc.total_round_cnt  = ATOMIC_GET(hfuzz->mutate.totalRoundCnt);
                }
                hfuzz_metrics_log_stats(
                    execs, pcs, edges, 0, 0,
                    /* sched (not available outside dynamic mode) */
                    0, 0.0f, 0.0f, 0.0f, 0.0f, 0, 0.0f, 0, 0, 0,
                    /* decay (not available outside dynamic mode) */
                    0, 0, 0, 0, 0, corpus, 0,
                    /* health */
                    avgExecTime, execTimeMax, execTimeSlow, 0.0f,
                    plateauSecs, queueWraps, maxDepth,
                    /* diff-fuzz */
                    uniqueCrashes, crashes, timeouts, 0, 0, 0, 0, 0, 0,
                    state_str, testedFiles, totalFiles,
                    truncatedTooLarge, &mc
                );
            }
        }
    }

    {
        fuzzState_t st = fuzz_getState(run->global);
        if (st == _HF_STATE_REPLAY) {
            run->mutationsPerRun = 0U;
            if (input_prepareStaticFile(run, /* rewind= */ false, /* mangle= */ false)) {
                return true;
            }
            return false;
        }
        if (st == _HF_STATE_DYNAMIC_DRY_RUN) {
            run->mutationsPerRun = 0U;
            if (input_prepareStaticFile(run, /* rewind= */ false, /* mangle= */ false)) {
                return true;
            }
            fuzz_setDynamicMainState(run);
            run->mutationsPerRun = run->global->mutate.mutationsPerRun;
        }
    }

    if (fuzz_getState(run->global) == _HF_STATE_DYNAMIC_MINIMIZE) {
        fuzz_minimizeRemoveFiles(run);
        return false;
    }

    if (fuzz_getState(run->global) == _HF_STATE_DYNAMIC_MAIN) {
        if (run->global->exe.externalCommand) {
            if (!input_prepareExternalFile(run)) {
                LOG_E("input_prepareExternalFile() failed");
                return false;
            }
        } else if (run->global->exe.feedbackMutateCommand) {
            if (!input_prepareDynamicInput(run, false)) {
                LOG_E("input_prepareDynamicInput(() failed");
                return false;
            }
        } else if (!input_prepareDynamicInput(run, !(run->global->exe.persistent && run->global->exe.useCustomMutator))) {
            LOG_E("input_prepareDynamicInput() failed");
            return false;
        }
    }

    if (fuzz_getState(run->global) == _HF_STATE_STATIC) {
        if (run->global->exe.externalCommand) {
            if (!input_prepareExternalFile(run)) {
                LOG_E("input_prepareExternalFile() failed");
                return false;
            }
        } else if (run->global->exe.feedbackMutateCommand) {
            if (!input_prepareStaticFile(run, /* rewind= */ true, /* mangle= */ false)) {
                LOG_E("input_prepareStaticFile() failed");
                return false;
            }
        } else if (!input_prepareStaticFile(run, /* rewind= */ true, /* mangle= */ !(run->global->exe.persistent && run->global->exe.useCustomMutator))) {
            LOG_E("input_prepareStaticFile() failed");
            return false;
        }
    }

    if (run->global->exe.postExternalCommand &&
        !input_postProcessFile(run, run->global->exe.postExternalCommand)) {
        LOG_E("input_postProcessFile('%s') failed", run->global->exe.postExternalCommand);
        return false;
    }

    if (run->global->exe.feedbackMutateCommand &&
        !input_postProcessFile(run, run->global->exe.feedbackMutateCommand)) {
        LOG_E("input_postProcessFile('%s') failed", run->global->exe.feedbackMutateCommand);
        return false;
    }

    /* Donor must be written before subproc_Run sends the size indicator */
    if (run->global->exe.persistent && run->global->exe.useCustomMutator
        && run->global->exe.useCrossover) {
        input_prepareDonorInput(run);
    }

    return true;
}

/*
 * coverage_data.bin - per-file guard coverage for greedy set-cover minimization
 *
 * All multi-byte integers are little-endian (native x86-64).
 *
 * Header (24 bytes):
 *   [0..4)   u8[4]   magic   "COVD" (0x43 0x4F 0x56 0x44)
 *   [4..8)   u32     version (currently 1)
 *   [8..16)  u64     guard_count: total instrumentation guards in the binary
 *   [16..24) u64     file_count:  number of entry records that follow
 *
 * guard_count and file_count are written as zero initially and backfilled
 * via pwrite() after all entries have been streamed.
 *
 * Entry (repeated file_count times):
 *   u16      filename_len
 *   u8[]     filename      (filename_len bytes, no NUL terminator)
 *   u32      hit_count:     number of distinct guard IDs hit by this file
 *   u32[]    guard_ids     (hit_count elements, each a guard index in [0, guard_count))
 */

static bool fuzz_coverageDataWriteHeader(int fd) {
    const uint8_t magic[4] = { 'C', 'O', 'V', 'D' };
    uint32_t      version  = 1;
    uint64_t      zero     = 0;
    return files_writeToFd(fd, magic, sizeof(magic))
        && files_writeToFd(fd, (const uint8_t*)&version, 4)
        && files_writeToFd(fd, (const uint8_t*)&zero, 8)
        && files_writeToFd(fd, (const uint8_t*)&zero, 8);
}

bool fuzz_coverageDataFinalizeHeader(int fd, uint64_t guardCount, uint64_t fileCount) {
    return TEMP_FAILURE_RETRY(pwrite(fd, &guardCount, 8, 8)) == 8
        && TEMP_FAILURE_RETRY(pwrite(fd, &fileCount, 8, 16)) == 8;
}

void fuzz_coverageDataAppendEntry(
        honggfuzz_t* hfuzz, const uint8_t* localMap, uint64_t guardNb, const char* base) {
    if (hfuzz->coverageData.fd < 0) return;
    if (guardNb > _HF_PC_GUARD_MAX) guardNb = _HF_PC_GUARD_MAX;

    uint32_t  localCnt = 0;
    uint32_t  localCap = 4096;
    uint32_t* localIds = malloc(localCap * sizeof(uint32_t));
    if (!localIds) {
        LOG_E("malloc(localIds) failed");
        return;
    }

    for (uint64_t i = 0; i < guardNb; i++) {
        if (localMap[i]) {
            if (localCnt >= localCap) {
                localCap *= 2;
                uint32_t* tmp = realloc(localIds, localCap * sizeof(uint32_t));
                if (!tmp) {
                    LOG_E("realloc(localIds, %u) failed", localCap);
                    free(localIds);
                    return;
                }
                localIds = tmp;
            }
            localIds[localCnt++] = (uint32_t)i;
        }
    }

    if (localCnt == 0) {
        free(localIds);
        return;
    }

    size_t baseLen = strlen(base);
    if (baseLen > UINT16_MAX) {
        LOG_W("Filename too long for coverage_data.bin (%zu bytes), skipping '%s'", baseLen, base);
        free(localIds);
        return;
    }
    uint16_t fnLen = (uint16_t)baseLen;

    size_t idsBytes  = localCnt * sizeof(uint32_t);
    size_t entrySize = sizeof(fnLen) + fnLen + sizeof(localCnt) + idsBytes;
    uint8_t* buf = malloc(entrySize);
    if (!buf) {
        LOG_E("malloc(entry, %zu) failed", entrySize);
        free(localIds);
        return;
    }

    size_t off = 0;
    memcpy(buf + off, &fnLen, sizeof(fnLen));       off += sizeof(fnLen);
    memcpy(buf + off, base, fnLen);                 off += fnLen;
    memcpy(buf + off, &localCnt, sizeof(localCnt)); off += sizeof(localCnt);
    memcpy(buf + off, localIds, idsBytes);

    free(localIds);

    MX_SCOPED_LOCK(&hfuzz->coverageData.entryMutex);
    if (!files_writeToFd(hfuzz->coverageData.fd, buf, entrySize)) {
        PLOG_W("Failed to write coverage_data.bin entry for '%s'", base);
    } else {
        ATOMIC_POST_INC(hfuzz->coverageData.entryCnt);
    }

    free(buf);
}

static void fuzz_replayRecordRequiredFile(honggfuzz_t* hfuzz, const char* base) {
    char* dup = strdup(base);
    if (!dup) {
        LOG_E("strdup('%s') failed", base);
        return;
    }

    MX_SCOPED_LOCK(&hfuzz->coverageRequired.requiredFilesMutex);
    size_t idx = ATOMIC_GET(hfuzz->coverageRequired.requiredFileCnt);
    if (idx >= hfuzz->coverageRequired.requiredFilesCap) {
        size_t newCap = hfuzz->coverageRequired.requiredFilesCap * 2;
        if (newCap < 1024) newCap = 1024;
        char** p = realloc(hfuzz->coverageRequired.requiredFiles, newCap * sizeof(char*));
        if (!p) {
            LOG_E("realloc(requiredFiles, %zu) failed", newCap);
            free(dup);
            return;
        }
        hfuzz->coverageRequired.requiredFiles    = p;
        hfuzz->coverageRequired.requiredFilesCap = newCap;
    }
    hfuzz->coverageRequired.requiredFiles[idx] = dup;
    ATOMIC_POST_INC(hfuzz->coverageRequired.requiredFileCnt);
}

static void fuzz_replayCoverageCheck(run_t* run) {
    honggfuzz_t* hfuzz = run->global;
    uint8_t* localMap = run->perThreadCovFeedbackMap;
    uint64_t guardNb  = atomic_load_explicit(&hfuzz->feedback.covFeedbackMap->guardNb, memory_order_relaxed);

    if (guardNb == 0) return;
    uint64_t cap = guardNb < _HF_PC_GUARD_MAX ? guardNb : _HF_PC_GUARD_MAX;

    uint8_t* covGuards = (uint8_t*)ATOMIC_GET(hfuzz->coverageRequired.coveredGuards);
    if (!covGuards) {
        MX_SCOPED_LOCK(&hfuzz->coverageRequired.requiredFilesMutex);
        covGuards = (uint8_t*)ATOMIC_GET(hfuzz->coverageRequired.coveredGuards);
        if (!covGuards) {
            covGuards = calloc(cap, 1);
            if (!covGuards) {
                LOG_E("calloc(coveredGuards, %" PRIu64 ") failed", cap);
                return;
            }
            ATOMIC_SET(hfuzz->coverageRequired.coveredGuardsSize, cap);
            ATOMIC_SET(hfuzz->coverageRequired.coveredGuards, covGuards);
            LOG_I("Allocated covered-guards bitmap: %" PRIu64 " guards", cap);
        }
    }

    uint64_t allocSize = ATOMIC_GET(hfuzz->coverageRequired.coveredGuardsSize);
    if (cap > allocSize) cap = allocSize;

    bool hasNew = false;
    for (uint64_t i = 0; i < cap; i++) {
        if (localMap[i] && !ATOMIC_GET(covGuards[i]) && ATOMIC_XCHG(covGuards[i], 1) == 0) {
            hasNew = true;
        }
    }

    /* Use basename: honggfuzz corpora are flat directories, no nested paths. */
    const char* fname = run->dynfile->path;
    const char* base = strrchr(fname, '/');
    base = base ? base + 1 : fname;

    if (hasNew) {
        fuzz_replayRecordRequiredFile(hfuzz, base);
    }

    fuzz_coverageDataAppendEntry(hfuzz, localMap, guardNb, base);
}

static void fuzz_fuzzLoop(run_t* run) {
    run->timeStartedUSecs = util_timeNowUSecs();
    run->crashFileName[0] = '\0';
    run->pc               = 0;
    run->backtrace        = 0;
    run->access           = 0;
    run->exception        = 0;
    run->report[0]        = '\0';
    run->mainWorker       = true;
    run->mutationsPerRun  = run->global->mutate.mutationsPerRun;
    run->tmOutSignaled    = false;
    run->donorSize        = 0;

    run->hwCnts.cpuInstrCnt  = 0;
    run->hwCnts.cpuBranchCnt = 0;
    run->hwCnts.bbCnt        = 0;
    run->hwCnts.newBBCnt     = 0;

    if (!fuzz_fetchInput(run)) {
        if (run->global->cfg.replay) {
            return;
        }
        if (run->global->cfg.minimize && fuzz_getState(run->global) == _HF_STATE_DYNAMIC_MINIMIZE) {
            fuzz_setTerminating();
            return;
        }
        LOG_F("Cound't prepare input for fuzzing");
    }
    if (!subproc_Run(run)) {
        LOG_F("Couldn't run fuzzed command");
    }

    /* Log execution metrics (optional - weak symbol, no-op if not overridden) */
    {
        uint64_t exec_time_us = util_timeNowUSecs() - run->timeStartedUSecs;
        hfuzz_metrics_log_execution(run->dynfile->size, exec_time_us);

        /* Sample every 256th execution for avg/slow stats (matches dashboard's >> 8 divisor) */
        uint64_t mutCnt = ATOMIC_GET(run->global->cnts.mutationsCnt);
        if ((mutCnt & 0xFF) == 0) {
            ATOMIC_POST_ADD(run->global->cnts.execTimeSum, exec_time_us);
            uint64_t sampledCount = mutCnt >> 8;
            if (sampledCount > 1) {
                uint64_t avg = ATOMIC_GET(run->global->cnts.execTimeSum) / sampledCount;
                if (exec_time_us > avg * 10) {
                    ATOMIC_POST_INC(run->global->cnts.execTimeSlowCnt);
                }
            }
        }
        /* Always track max (race-tolerant, same pattern as energyMax) */
        uint64_t curMax = ATOMIC_GET(run->global->cnts.execTimeMax);
        if (exec_time_us > curMax) {
            ATOMIC_SET(run->global->cnts.execTimeMax, exec_time_us);
        }
    }

    if (run->global->cfg.replay) {
        if (run->perThreadCovFeedbackMap && run->global->io.covDirNew) {
            fuzz_replayCoverageCheck(run);
        }
    } else {
        if (run->global->feedback.dynFileMethod != _HF_DYNFILE_NONE) {
            fuzz_perfFeedback(run);
        }
        if (run->global->cfg.useVerifier && !fuzz_runVerifier(run)) {
            return;
        }
        report_saveReport(run);
    }
}

static void fuzz_fuzzLoopSocket(run_t* run) {
    run->timeStartedUSecs = util_timeNowUSecs();
    run->crashFileName[0] = '\0';
    run->pc               = 0;
    run->backtrace        = 0;
    run->access           = 0;
    run->exception        = 0;
    run->report[0]        = '\0';
    run->mainWorker       = true;
    run->mutationsPerRun  = run->global->mutate.mutationsPerRun;
    run->tmOutSignaled    = false;

    run->hwCnts.cpuInstrCnt  = 0;
    run->hwCnts.cpuBranchCnt = 0;
    run->hwCnts.bbCnt        = 0;
    run->hwCnts.newBBCnt     = 0;

    LOG_I("------------------------------------------------------");

    /* First iteration - start target
       Other iterations - re-start target, if necessary
       subproc_Run() will decide by itself if a restart is necessary, via
       subproc_New()
    */
    LOG_D("------[ 1: subproc_run");
    if (!subproc_Run(run)) {
        LOG_W("Couldn't run server");
    }

    /* Tell the external fuzzer to send data to target
       The fuzzer will notify us when finished; block until then.
    */
    LOG_D("------[ 2: fetch input");
    if (!fuzz_waitForExternalInput(run)) {
        /* Fuzzer could not connect to target, and told us to
           restart it. Do it on the next iteration.
           or: it crashed by fuzzing. Restart it too.
           */
        LOG_D("------[ 2.1: Target down, will restart it");
        run->pid = 0;    // make subproc_Run() restart it on next iteration
        return;
    }

    LOG_D("------[ 3: feedback");
    if (run->global->feedback.dynFileMethod != _HF_DYNFILE_NONE) {
        fuzz_perfFeedback(run);
    }
    if (run->global->cfg.useVerifier && !fuzz_runVerifier(run)) {
        return;
    }

    report_saveReport(run);
}

static void* fuzz_threadNew(void* arg) {
    honggfuzz_t* hfuzz  = (honggfuzz_t*)arg;
    unsigned int fuzzNo = ATOMIC_POST_INC(hfuzz->threads.threadsActiveCnt);
    LOG_I("Launched new fuzzing thread, no. #%u", fuzzNo);

    if (!util_PinThreadToCPUs(fuzzNo, hfuzz->threads.pinThreadToCPUs)) {
        PLOG_W("Pinning thread #%u to %" PRIu32 " CPUs failed", fuzzNo,
            hfuzz->threads.pinThreadToCPUs);
    }

    run_t run = {
        .global           = hfuzz,
        .pid              = 0,
        .dynfile          = (dynfile_t*)util_Calloc(sizeof(dynfile_t) + hfuzz->io.maxFileSz),
        .fuzzNo           = fuzzNo,
        .persistentSock   = -1,
        .tmOutSignaled    = false,
        .pendingStatsLog  = false,
    };
    defer {
        free(run.dynfile);
    };

    /* Do not try to handle input files with socketfuzzer */
    char mapname[32];
    snprintf(mapname, sizeof(mapname), "hf-%u-input", fuzzNo);
    if (!hfuzz->socketFuzzer.enabled) {
        size_t mmapSz = hfuzz->mutate.maxInputSz;
        if (hfuzz->exe.persistent && hfuzz->exe.useCustomMutator && hfuzz->exe.useCrossover) {
            mmapSz *= 2;
        }
        if (!(run.dynfile->data = files_mapSharedMem(mmapSz, &(run.dynfile->fd),
                  mapname, /* nocore= */ true, /* exportmap= */ false))) {
            LOG_F("Couldn't create an input file of size: %zu, name:'%s'", mmapSz, mapname);
        }
    }
    defer {
        if (run.dynfile->fd != -1) {
            close(run.dynfile->fd);
        }
    };

    snprintf(mapname, sizeof(mapname), "hf-%u-perthreadmap", fuzzNo);
    if ((run.perThreadCovFeedbackFd = files_createSharedMem(sizeof(feedback_t), mapname,
             /* exportmap= */ run.global->io.exportFeedback)) == -1) {
        LOG_F("files_createSharedMem(name='%s', sz=%zu, dir='%s') failed", mapname,
            sizeof(feedback_t), run.global->io.workDir);
    }
    run.perThreadCovFeedbackMap = NULL;
    /* Needed in both modes now: replay reads it per corpus file, fuzzing reads it for
     * each input exported to --covdir_new.  The persistent child clears it at the top
     * of every HonggfuzzRunOneInput (instrumentResetLocalCovFeedback), so it holds the
     * guards of the input just executed.
     *
     * Same condition as the coverage_data.bin fd in fuzz_threadsStart, so a target that
     * cannot produce per-input guards does not map _HF_PC_GUARD_MAX (128 MiB) per
     * thread to never read it. */
    if (run.global->io.covDirNew && (run.global->cfg.replay || run.global->exe.persistent)) {
        _Static_assert(
            offsetof(feedback_t, pcGuardMap) == 0, "mmap at offset 0 assumes pcGuardMap is first");
        int mflags = files_getTmpMapFlags(MAP_SHARED, /* nocore= */ true);
        void* m = mmap(NULL, _HF_PC_GUARD_MAX, PROT_READ,
            mflags, run.perThreadCovFeedbackFd, 0);
        if (m == MAP_FAILED) {
            LOG_W("mmap(perThreadCovFeedbackFd) failed for thread %u", fuzzNo);
        } else {
#if defined(MADV_DONTDUMP)
            madvise(m, _HF_PC_GUARD_MAX, MADV_DONTDUMP);
#endif
            run.perThreadCovFeedbackMap = (uint8_t*)m;
        }
    }
    defer {
        if (run.perThreadCovFeedbackMap) {
            munmap(run.perThreadCovFeedbackMap, _HF_PC_GUARD_MAX);
        }
        if (run.perThreadCovFeedbackFd != -1) {
            close(run.perThreadCovFeedbackFd);
        }
    };

    if (!arch_archThreadInit(&run)) {
        LOG_F("Could not initialize the thread");
    }

    for (;;) {
        /* Replay mode or dry-run+verifier: exit after all static files processed */
        if (run.global->cfg.replay ||
            (run.global->mutate.mutationsPerRun == 0U && run.global->cfg.useVerifier &&
             !hfuzz->socketFuzzer.enabled)) {
            if (ATOMIC_POST_INC(run.global->cnts.mutationsCnt) >= run.global->io.fileCnt) {
                break;
            }
        }
        /* Check for max iterations limit if set */
        else if ((ATOMIC_POST_INC(run.global->cnts.mutationsCnt) >=
                     run.global->mutate.mutationsMax) &&
                 run.global->mutate.mutationsMax) {
            break;
        }

        if (hfuzz->socketFuzzer.enabled) {
            fuzz_fuzzLoopSocket(&run);
        } else {
            fuzz_fuzzLoop(&run);
        }

        if (fuzz_isTerminating()) {
            break;
        }

        if (run.global->cfg.exitUponCrash && ATOMIC_GET(run.global->cnts.crashesCnt) > 0) {
            LOG_I("Seen a crash. Terminating all fuzzing threads");
            fuzz_setTerminating();
            break;
        }
    }

    arch_reapKill();

    if (run.pid) {
        if (hfuzz->cfg.replay && run.persistentSock != -1) {
            /* Graceful shutdown: close socket so the child's fetch loop sees
               EOF and calls exit(0), which fires atexit handlers (e.g. LLVM
               profile data writer for profraw generation). */
            close(run.persistentSock);
            run.persistentSock = -1;
            int status;
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 250000000}; /* 250ms */
            nanosleep(&ts, NULL);
            if (waitpid(run.pid, &status, WNOHANG) <= 0) {
                kill(run.pid, SIGKILL);
            }
        } else {
            kill(run.pid, SIGKILL);
        }
    }

    size_t j = ATOMIC_PRE_INC(run.global->threads.threadsFinished);
    size_t total = hfuzz->threads.threadsMax;
    LOG_I("Terminating thread no. #%" PRId32 ", left: %zu", fuzzNo,
          j < total ? total - j : 0);
    return NULL;
}

/* Not replay-only despite the history: during fuzzing the same file is written, one
 * entry per input exported to --covdir_new.  Octane reads it to compute guards_novel /
 * guards_merged, which read a uniform zero for every fuzzing job for as long as this
 * was gated on cfg.replay -- so the one number that would independently corroborate a
 * job's reported discovery count carried no signal at all.
 *
 * Attributing guards to one input requires the per-thread map to be reset between
 * executions, and only the persistent-mode child does that:
 * instrumentResetLocalCovFeedback() at the top of HonggfuzzRunOneInput().  A
 * non-persistent target maps the same per-thread file on every exec and
 * initializeLocalCovFeedback() does not clear it, so its guards accumulate over the
 * worker's whole history and every entry would overstate its input.  Hence the
 * persistent requirement below -- record nothing rather than something wrong. */
static void fuzz_coverageDataInit(honggfuzz_t* hfuzz) {
    if (pthread_mutex_init(&hfuzz->coverageRequired.requiredFilesMutex, NULL) != 0) {
        PLOG_F("pthread_mutex_init(requiredFilesMutex)");
    }

    char cov_path[PATH_MAX];
    int cp = snprintf(cov_path, sizeof(cov_path), "%s/coverage_data.bin", hfuzz->io.covDirNew);
    if (cp < 0 || (size_t)cp >= sizeof(cov_path)) {
        LOG_E("coverage_data.bin path too long (covDirNew='%s')", hfuzz->io.covDirNew);
        return;
    }

    hfuzz->coverageData.fd = TEMP_FAILURE_RETRY(
        open(cov_path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644));
    if (hfuzz->coverageData.fd < 0) {
        PLOG_W("Failed to open %s for coverage data", cov_path);
        return;
    }

    if (pthread_mutex_init(&hfuzz->coverageData.entryMutex, NULL) != 0) {
        PLOG_F("pthread_mutex_init(entryMutex)");
    }
    hfuzz->coverageData.entryCnt = 0;
    if (!fuzz_coverageDataWriteHeader(hfuzz->coverageData.fd)) {
        PLOG_W("Failed to write coverage_data.bin header");
        close(hfuzz->coverageData.fd);
        hfuzz->coverageData.fd = -1;
    }
}

void fuzz_threadsStart(honggfuzz_t* hfuzz) {
    /* Re-init the dynfileq rwlock at runtime as a workaround for:
       https://sourceware.org/bugzilla/show_bug.cgi?id=23844 */
    if (pthread_rwlock_init(&hfuzz->mutex.dynfileq, NULL) != 0) {
        PLOG_F("pthread_rwlock_init(dynfileq)");
    }

    if (!arch_archInit(hfuzz)) {
        LOG_F("Couldn't prepare arch for fuzzing");
    }
    if (!sanitizers_Init(hfuzz)) {
        LOG_F("Couldn't prepare sanitizer options");
    }

    hfuzz->coverageData.fd = -1;
    if (hfuzz->io.covDirNew) {
        /* Replay is unchanged -- it predates this and drives the map one corpus file at
         * a time.  For fuzzing the map is only per-input under persistent mode. */
        if (hfuzz->cfg.replay || hfuzz->exe.persistent) {
            fuzz_coverageDataInit(hfuzz);
        } else {
            /* Reachable in practice only for targets built without hfuzz-cc: linking
             * libhfuzz embeds _HF_PERSISTENT_SIG, so anything instrumented the normal
             * way is detected as persistent above.  Such a target registers no guards,
             * so there would be nothing to record anyway.
             *
             * A target instrumented some other way and genuinely not persistent could
             * in principle be supported now -- initializeLocalCovFeedback() clears the
             * inherited map in every freshly exec'd child, and for one-exec-per-input
             * that is per-input attribution.  Left out because it could not be
             * exercised here to confirm it. */
            LOG_W("--covdir_new: not recording coverage_data.bin -- this target is not "
                  "persistent, so per-input guard attribution is not established for it "
                  "(a target built with hfuzz-cc is always detected as persistent; one "
                  "that is not is typically uninstrumented and has no guards to record)");
        }
    }

    if (hfuzz->cfg.replay) {
        LOG_I("Entering Replay mode (coverage collection)");
        hfuzz->feedback.state = _HF_STATE_REPLAY;
        hfuzz->feedback.dynFileMethod |= _HF_DYNFILE_SOFT;
        hfuzz->mutate.mutationsPerRun = 0;
    } else if (hfuzz->socketFuzzer.enabled) {
        /* Don't do dry run with socketFuzzer */
        LOG_I("Entering phase - Feedback Driven Mode (SocketFuzzer)");
        hfuzz->feedback.state = _HF_STATE_DYNAMIC_MAIN;
    } else if (hfuzz->feedback.dynFileMethod != _HF_DYNFILE_NONE) {
        LOG_I("Entering phase 1/3: Dry Run");
        hfuzz->feedback.state = _HF_STATE_DYNAMIC_DRY_RUN;

    } else {
        LOG_I("Entering phase: Static");
        hfuzz->feedback.state = _HF_STATE_STATIC;
    }

    for (size_t i = 0; i < hfuzz->threads.threadsMax; i++) {
        if (!subproc_runThread(
                hfuzz, &hfuzz->threads.threads[i], fuzz_threadNew, /* joinable= */ true)) {
            PLOG_F("Couldn't run a thread #%zu", i);
        }
        /* Stagger thread creation to avoid thundering-herd contention on the
           dynfileq rwlock exacerbating
           https://sourceware.org/bugzilla/show_bug.cgi?id=23844 */
        usleep(1000);
    }
}
