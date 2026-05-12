/*
 *
 * honggfuzz - reporting
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
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

#include "report.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

static int reportFD = -1;

#if defined(_HF_ARCH_LINUX)
static void report_printdynFileMethod(run_t* run) {
    dprintf(reportFD, " dynFileMethod   : ");
    if (run->global->feedback.dynFileMethod == 0)
        dprintf(reportFD, "NONE\n");
    else {
        if (run->global->feedback.dynFileMethod & _HF_DYNFILE_INSTR_COUNT)
            dprintf(reportFD, "INSTR_COUNT ");
        if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BRANCH_COUNT)
            dprintf(reportFD, "BRANCH_COUNT ");
        if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BTS_EDGE)
            dprintf(reportFD, "BTS_EDGE_COUNT ");
        if (run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_BLOCK)
            dprintf(reportFD, "IPT_BLOCK_COUNT ");

        dprintf(reportFD, "\n");
    }
}
#endif

static void report_printTargetCmd(run_t* run) {
    dprintf(reportFD, " fuzzTarget      : ");
    for (int x = 0; run->global->exe.cmdline[x]; x++) {
        dprintf(reportFD, "%s ", run->global->exe.cmdline[x]);
    }
    dprintf(reportFD, "\n");
}

void report_saveReport(run_t* run) {
    if (run->report[0] == '\0') {
        return;
    }

    MX_SCOPED_LOCK(&run->global->mutex.report);

    if (reportFD == -1) {
        char reportFName[PATH_MAX];
        if (run->global->cfg.reportFile == NULL) {
            snprintf(reportFName, sizeof(reportFName), "%s/%s", run->global->io.workDir,
                _HF_REPORT_FILE);
        } else {
            snprintf(reportFName, sizeof(reportFName), "%s", run->global->cfg.reportFile);
        }

        reportFD =
            TEMP_FAILURE_RETRY(open(reportFName, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644));
        if (reportFD == -1) {
            PLOG_F("Couldn't open('%s') for writing", reportFName);
        }
    }

    char localtmstr[HF_STR_LEN];
    util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));

    dprintf(reportFD,
        "=====================================================================\n"
        "TIME: %s\n"
        "=====================================================================\n"
        "FUZZER ARGS:\n"
        " mutationsPerRun : %u\n"
        " externalCmd     : %s\n"
        " fuzzStdin       : %s\n"
        " timeout         : %ld (sec)\n"
#if defined(_HF_ARCH_LINUX) || defined(_HF_ARCH_NETBSD)
        " ignoreAddr      : %p\n"
#endif
        " ASLimit         : %" PRIu64 " (MiB)\n"
        " RSSLimit        : %" PRIu64 " (MiB)\n"
        " DATALimit       : %" PRIu64 " (MiB)\n"
        " wordlistFile    : %s\n",
        localtmstr, run->global->mutate.mutationsPerRun,
        run->global->exe.externalCommand == NULL ? "NULL" : run->global->exe.externalCommand,
        run->global->exe.fuzzStdin ? "TRUE" : "FALSE", (long)run->global->timing.tmOut,
#if defined(_HF_ARCH_LINUX)
        run->global->arch_linux.ignoreAddr,
#elif defined(_HF_ARCH_NETBSD)
        run->global->arch_netbsd.ignoreAddr,
#endif
        run->global->exe.asLimit, run->global->exe.rssLimit, run->global->exe.dataLimit,
        run->global->mutate.dictionaryFile == NULL ? "NULL" : run->global->mutate.dictionaryFile);

#if defined(_HF_ARCH_LINUX)
    report_printdynFileMethod(run);
#endif

    report_printTargetCmd(run);

    dprintf(reportFD,
        "%s"
        "=====================================================================\n",
        run->report);
}

void report_appendReport(pid_t pid, run_t* run, funcs_t* funcs, size_t funcCnt, uint64_t pc,
    uint64_t crashAddr, int signo, const char* instr, const char description[HF_STR_LEN]) {
    util_ssnprintf(run->report, sizeof(run->report), "CRASH:\n");
    util_ssnprintf(run->report, sizeof(run->report), "DESCRIPTION: %s\n", description);
    util_ssnprintf(run->report, sizeof(run->report), "ORIG_FNAME: %s\n", run->dynfile->path);
    util_ssnprintf(run->report, sizeof(run->report), "FUZZ_FNAME: %s\n", run->crashFileName);
    util_ssnprintf(run->report, sizeof(run->report), "PID: %d\n", (int)pid);
    util_ssnprintf(
        run->report, sizeof(run->report), "SIGNAL: %s (%d)\n", util_sigName(signo), signo);
    util_ssnprintf(run->report, sizeof(run->report), "PC: 0x%" PRIx64 "\n", pc);
    util_ssnprintf(run->report, sizeof(run->report), "FAULT ADDRESS: 0x%" PRIx64 "\n", crashAddr);
    util_ssnprintf(run->report, sizeof(run->report), "INSTRUCTION: %s\n", instr);
    util_ssnprintf(
        run->report, sizeof(run->report), "STACK HASH: %016" PRIx64 "\n", run->backtrace);
    util_ssnprintf(run->report, sizeof(run->report), "STACK:\n");
    for (size_t i = 0; i < funcCnt; i++) {
        util_ssnprintf(run->report, sizeof(run->report), " <0x%016tx> ", (uintptr_t)funcs[i].pc);
        util_ssnprintf(run->report, sizeof(run->report), "[func:%s file:%s line:%zu module:%s]\n",
            funcs[i].func, funcs[i].file, funcs[i].line, funcs[i].module);
    }

// libunwind is not working for 32bit targets in 64bit systems
#if defined(__aarch64__)
    if (funcCnt == 0) {
        util_ssnprintf(run->report, sizeof(run->report),
            " !ERROR: If 32bit fuzz target"
            " in aarch64 system, try ARM 32bit build\n");
    }
#endif

    util_ssnprintf(run->report, sizeof(run->report),
        "INPUT_SIZE: %zu\n", run->dynfile ? run->dynfile->size : 0);
    util_ssnprintf(run->report, sizeof(run->report),
        "MUTATIONS_PER_RUN: %u\n", run->mutationsPerRun);
    util_ssnprintf(run->report, sizeof(run->report),
        "MUTATION_DEPTH: %u\n", run->dynfile ? run->dynfile->depth : 0);
    util_ssnprintf(run->report, sizeof(run->report),
        "SELECT_COUNT: %u\n", run->dynfile ? run->dynfile->selectCnt : 0);

    return;
}

void report_appendTimeoutReport(run_t* run, int64_t elapsedUSecs, int64_t effectiveTmOutSecs,
    int64_t tmOutMultiplier, const char* signalUsed, const char* phaseStr,
    const char* timeoutFileName, size_t inputSize, const char* procStack,
    const char* procWchan, long ctxVoluntary, long ctxInvoluntary,
    long cpuUtimeTicks, long cpuStimeTicks, long vmRSSKb, const double loadAvg[3],
    int64_t ioReadBytes, int64_t ioWriteBytes, int64_t schedRunNs, int64_t schedWaitNs) {
    int64_t elapsedSecs = elapsedUSecs / 1000000;
    int64_t elapsedMs   = (elapsedUSecs % 1000000) / 1000;

    util_ssnprintf(run->report, sizeof(run->report), "TIMEOUT:\n");
    util_ssnprintf(run->report, sizeof(run->report),
        "DESCRIPTION: Process exceeded %lds timeout (effective %" PRId64
        "s, phase %s, x%" PRId64 " multiplier)\n",
        (long)run->global->timing.tmOut, effectiveTmOutSecs, phaseStr, tmOutMultiplier);
    util_ssnprintf(run->report, sizeof(run->report),
        "ELAPSED: %" PRId64 ".%03" PRId64 "s\n", elapsedSecs, elapsedMs);
    util_ssnprintf(run->report, sizeof(run->report),
        "CONFIGURED_TIMEOUT: %lds\n", (long)run->global->timing.tmOut);
    util_ssnprintf(run->report, sizeof(run->report),
        "EFFECTIVE_TIMEOUT: %" PRId64 "s (phase %s, x%" PRId64 " multiplier)\n",
        effectiveTmOutSecs, phaseStr, tmOutMultiplier);
    util_ssnprintf(run->report, sizeof(run->report), "PHASE: %s\n", phaseStr);
    util_ssnprintf(run->report, sizeof(run->report), "SIGNAL: %s\n", signalUsed);
    util_ssnprintf(run->report, sizeof(run->report),
        "ORIG_FNAME: %s\n", run->dynfile ? run->dynfile->path : "N/A");
    util_ssnprintf(run->report, sizeof(run->report),
        "FUZZ_FNAME: %s\n", timeoutFileName[0] ? timeoutFileName : "N/A");
    util_ssnprintf(run->report, sizeof(run->report), "INPUT_SIZE: %zu\n", inputSize);
    util_ssnprintf(run->report, sizeof(run->report),
        "MUTATIONS_PER_RUN: %u\n", run->mutationsPerRun);
    util_ssnprintf(run->report, sizeof(run->report),
        "MUTATION_DEPTH: %u\n", run->dynfile ? run->dynfile->depth : 0);
    util_ssnprintf(run->report, sizeof(run->report),
        "SELECT_COUNT: %u\n", run->dynfile ? run->dynfile->selectCnt : 0);
    util_ssnprintf(run->report, sizeof(run->report), "PID: %d\n", (int)run->pid);

    /* CPU time: if available, compute utilization percentage */
    if (cpuUtimeTicks >= 0 && cpuStimeTicks >= 0) {
        long hz = sysconf(_SC_CLK_TCK);
        if (hz <= 0) hz = 100;
        double cpuTimeSecs = (double)(cpuUtimeTicks + cpuStimeTicks) / (double)hz;
        double wallTimeSecs = (double)elapsedUSecs / 1000000.0;
        double cpuPct = wallTimeSecs > 0.0 ? (cpuTimeSecs / wallTimeSecs) * 100.0 : 0.0;
        util_ssnprintf(run->report, sizeof(run->report),
            "CPU_TIME: %.3fs (user=%ld stime=%ld ticks, %.1f%% utilization)\n",
            cpuTimeSecs, cpuUtimeTicks, cpuStimeTicks, cpuPct);
    }
    if (vmRSSKb >= 0) {
        util_ssnprintf(run->report, sizeof(run->report),
            "VM_RSS: %ld kB\n", vmRSSKb);
    }
    if (loadAvg[0] >= 0.0) {
        util_ssnprintf(run->report, sizeof(run->report),
            "LOAD_AVG: %.2f %.2f %.2f\n", loadAvg[0], loadAvg[1], loadAvg[2]);
    }
    if (ioReadBytes >= 0 || ioWriteBytes >= 0) {
        util_ssnprintf(run->report, sizeof(run->report),
            "IO: read=%" PRId64 " write=%" PRId64 " bytes\n", ioReadBytes, ioWriteBytes);
    }
    if (schedRunNs >= 0 && schedWaitNs >= 0) {
        double runMs  = (double)schedRunNs / 1e6;
        double waitMs = (double)schedWaitNs / 1e6;
        double totalMs = runMs + waitMs;
        double schedPct = totalMs > 0.0 ? (runMs / totalMs) * 100.0 : 0.0;
        util_ssnprintf(run->report, sizeof(run->report),
            "SCHED: run=%.1fms wait=%.1fms (%.1f%% on-cpu)\n", runMs, waitMs, schedPct);
    }
    if (procWchan[0] != '\0') {
        util_ssnprintf(run->report, sizeof(run->report), "WCHAN: %s\n", procWchan);
    }
    if (ctxVoluntary >= 0 || ctxInvoluntary >= 0) {
        util_ssnprintf(run->report, sizeof(run->report),
            "CTX_SWITCHES: voluntary=%ld involuntary=%ld\n", ctxVoluntary, ctxInvoluntary);
    }
    if (procStack[0] != '\0') {
        util_ssnprintf(run->report, sizeof(run->report), "KERNEL STACK:\n%s\n", procStack);
    }
}
