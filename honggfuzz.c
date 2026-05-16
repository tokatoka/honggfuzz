/*
 *
 * honggfuzz - the main file
 * -----------------------------------------
 *
 * Authors: Robert Swiecki <swiecki@google.com>
 *          Felix Gröbert <groebert@google.com>
 *
 * Copyright 2010-2019 by Google Inc. All Rights Reserved.
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__FreeBSD__)
#include <sys/procctl.h>
#endif

#if defined(_HF_ARCH_LINUX)
#include <ucontext.h>
#endif

#include "cmdline.h"
#include "dict.h"
#include "display.h"
#include "fuzz.h"
#include "git_buildinfo.h"
#include "input.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "socketfuzzer.h"
#include "subproc.h"
#include "hfuzz_metrics.h"

extern int hfuzz_write_coverage_required_json(
    const char* path, const char* const* files, size_t count) __attribute__((weak));

#if defined(_HF_ARCH_LINUX) && !defined(_HF_LINUX_NO_BFD)
#include "linux/bfd.h"
#endif

static int  sigReceived = 0;
static bool clearWin    = false;

/*
 * CygWin/MinGW incorrectly copies stack during fork(), so we need to keep some
 * structures in the data section
 */
honggfuzz_t hfuzz;

/*
 * atexit handler: dump diagnostic context on non-zero exit (exit code 1
 * from LOG_F, etc.) so the worker log shows WHY honggfuzz died.
 */
static void atexitDiagnostics(void) {
    /* Only dump on abnormal exit. We check sigReceived to skip clean
     * shutdown (SIGTERM/SIGINT) which also calls exit(). */
    if (ATOMIC_GET(sigReceived) != 0) {
        return; /* Clean shutdown via SIGTERM/SIGINT, no diagnostics needed */
    }

    /* Read cgroup memory state */
    int64_t cg_cur = -1, cg_max = -1;
    FILE* cgf = fopen("/proc/self/cgroup", "r");
    if (cgf) {
        char cgline[PATH_MAX];
        char cgpath[PATH_MAX] = "";
        while (fgets(cgline, sizeof(cgline), cgf)) {
            if (strncmp(cgline, "0::", 3) == 0) {
                char* nl = strchr(cgline + 3, '\n');
                if (nl) *nl = '\0';
                snprintf(cgpath, sizeof(cgpath), "%s", cgline + 3);
                break;
            }
        }
        fclose(cgf);
        if (cgpath[0] != '\0') {
            char path[PATH_MAX];
            FILE* f;
            int64_t v;
            snprintf(path, sizeof(path), "/sys/fs/cgroup%s/memory.current", cgpath);
            if ((f = fopen(path, "r")) != NULL) {
                if (fscanf(f, "%" PRId64, &v) == 1) cg_cur = v / (1024 * 1024);
                fclose(f);
            }
            snprintf(path, sizeof(path), "/sys/fs/cgroup%s/memory.max", cgpath);
            if ((f = fopen(path, "r")) != NULL) {
                if (fscanf(f, "%" PRId64, &v) == 1) cg_max = v / (1024 * 1024);
                fclose(f);
            }
        }
    }

    /* Read host MemAvailable */
    int64_t host_avail = -1;
    FILE* mi = fopen("/proc/meminfo", "r");
    if (mi) {
        char mline[256];
        while (fgets(mline, sizeof(mline), mi)) {
            int64_t v;
            if (sscanf(mline, "MemAvailable: %" PRId64 " kB", &v) == 1) {
                host_avail = v / 1024;
                break;
            }
        }
        fclose(mi);
    }

    fprintf(stderr,
        "\n"
        "================================================================\n"
        "honggfuzz parent exiting abnormally (pid=%d)\n"
        "  cgroup memory: %" PRId64 " / %" PRId64 " MB\n"
        "  host available: %" PRId64 " MB\n"
        "  mutations: %" PRIu64 ", crashes: %" PRIu64 "\n"
        "  persistent resets: %" PRIu64 "\n"
        "================================================================\n",
        (int)getpid(),
        cg_cur, cg_max,
        host_avail,
        (uint64_t)ATOMIC_GET(hfuzz.cnts.mutationsCnt),
        (uint64_t)ATOMIC_GET(hfuzz.cnts.crashesCnt),
        (uint64_t)ATOMIC_GET(hfuzz.cnts.persistentResets));
}

static void exitWithMsg(const char* msg, int exit_code) {
    HF_ATTR_UNUSED ssize_t sz = write(STDERR_FILENO, msg, strlen(msg));
    for (;;) {
        exit(exit_code);
        _exit(exit_code);
        abort();
        __builtin_trap();
    }
}

/*
 * Diagnostic handler for fatal signals (SIGBUS, SIGSEGV, SIGABRT, SIGFPE,
 * SIGILL) in the honggfuzz parent process.  Logs the faulting address,
 * signal code, and instruction pointer before re-raising so a core dump
 * is produced.  Uses only async-signal-safe calls.
 */
static const char* fatalSigCodeStr(int sig, int code) {
    if (sig == SIGBUS) {
        switch (code) {
        case BUS_ADRALN: return "BUS_ADRALN (alignment)";
        case BUS_ADRERR: return "BUS_ADRERR (nonexistent phys addr)";
        case BUS_OBJERR: return "BUS_OBJERR (object-specific hw error)";
#ifdef BUS_MCEERR_AR
        case BUS_MCEERR_AR: return "BUS_MCEERR_AR (hw memory error, action required)";
#endif
#ifdef BUS_MCEERR_AO
        case BUS_MCEERR_AO: return "BUS_MCEERR_AO (hw memory error, action optional)";
#endif
        default: return "unknown";
        }
    }
    if (sig == SIGSEGV) {
        switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR (address not mapped)";
        case SEGV_ACCERR: return "SEGV_ACCERR (invalid permissions)";
#ifdef SEGV_BNDERR
        case SEGV_BNDERR: return "SEGV_BNDERR (bounds check fail)";
#endif
#ifdef SEGV_PKUERR
        case SEGV_PKUERR: return "SEGV_PKUERR (protection key fault)";
#endif
        default: return "unknown";
        }
    }
    if (sig == SIGFPE) {
        switch (code) {
        case FPE_INTDIV: return "FPE_INTDIV (integer divide by zero)";
        case FPE_INTOVF: return "FPE_INTOVF (integer overflow)";
        case FPE_FLTDIV: return "FPE_FLTDIV (float divide by zero)";
        case FPE_FLTOVF: return "FPE_FLTOVF (float overflow)";
        case FPE_FLTUND: return "FPE_FLTUND (float underflow)";
        default: return "unknown";
        }
    }
    if (sig == SIGILL) {
        switch (code) {
        case ILL_ILLOPC: return "ILL_ILLOPC (illegal opcode)";
        case ILL_ILLOPN: return "ILL_ILLOPN (illegal operand)";
        case ILL_PRVOPC: return "ILL_PRVOPC (privileged opcode)";
        default: return "unknown";
        }
    }
    return "unknown";
}

static const char* fatalSigName(int sig) {
    switch (sig) {
    case SIGBUS:  return "SIGBUS";
    case SIGSEGV: return "SIGSEGV";
    case SIGABRT: return "SIGABRT";
    case SIGFPE:  return "SIGFPE";
    case SIGILL:  return "SIGILL";
    default:      return "UNKNOWN";
    }
}

static void fatalSignalHandler(int sig, siginfo_t* si, void* ucontext) {
    /* Get instruction pointer from ucontext */
    uintptr_t pc = 0;
#if defined(_HF_ARCH_LINUX) && defined(__x86_64__)
    ucontext_t* uc = (ucontext_t*)ucontext;
    if (uc) {
        pc = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    }
#elif defined(_HF_ARCH_LINUX) && defined(__aarch64__)
    ucontext_t* uc = (ucontext_t*)ucontext;
    if (uc) {
        pc = (uintptr_t)uc->uc_mcontext.pc;
    }
#else
    (void)ucontext;
#endif

    dprintf(STDERR_FILENO,
        "\n\n"
        "================================================================\n"
        "FATAL %s in honggfuzz parent process (pid=%d)\n"
        "  si_addr  = %p (faulting address)\n"
        "  si_code  = %d (%s)\n"
        "  RIP/PC   = 0x%lx\n"
        "================================================================\n"
        "Re-raising for core dump. If no core is produced, check:\n"
        "  ulimit -c unlimited\n"
        "  kernel.core_pattern\n"
        "  HF_DONTDUMP=0 (includes shared memory in core)\n"
        "================================================================\n\n",
        fatalSigName(sig),
        (int)getpid(),
        si->si_addr,
        si->si_code, fatalSigCodeStr(sig, si->si_code),
        (unsigned long)pc);

    /* Re-raise with default handler so the kernel produces a core dump */
    struct sigaction sa_default;
    memset(&sa_default, 0, sizeof(sa_default));
    sa_default.sa_handler = SIG_DFL;
    sigaction(sig, &sa_default, NULL);
    raise(sig);
}

static void sigHandler(int sig) {
    /* We should not terminate upon SIGALRM delivery */
    if (sig == SIGALRM) {
        if (fuzz_shouldTerminate()) {
            exitWithMsg("Terminating forcefully\n", EXIT_FAILURE);
        }
        return;
    }
    if (sig == SIGWINCH) {
        ATOMIC_SET(clearWin, true);
        return;
    }

    /* It's handled in the signal thread */
    if (sig == SIGCHLD) {
        return;
    }

    if (ATOMIC_GET(sigReceived) != 0) {
        exitWithMsg("Repeated termination signal caught\n", EXIT_FAILURE);
    }

    ATOMIC_SET(sigReceived, sig);
}

static void setupRLimits(void) {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        PLOG_W("getrlimit(RLIMIT_NOFILE)");
        return;
    }
    if (rlim.rlim_cur >= 1024) {
        return;
    }
    if (rlim.rlim_max < 1024) {
        LOG_E("RLIMIT_NOFILE max limit < 1024 (%zu). Expect troubles!", (size_t)rlim.rlim_max);
        return;
    }
    rlim.rlim_cur = HF_MIN(1024, rlim.rlim_max);    // we don't need more
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        PLOG_E("Couldn't setrlimit(RLIMIT_NOFILE, cur=%zu/max=%zu)", (size_t)rlim.rlim_cur,
            (size_t)rlim.rlim_max);
    }
}

static void setupMainThreadTimer(void) {
    const struct itimerval it = {
        .it_value =
            {
                .tv_sec  = 1,
                .tv_usec = 0,
            },
        .it_interval =
            {
                .tv_sec  = 0,
                .tv_usec = 1000ULL * 200ULL,
            },
    };
    if (setitimer(ITIMER_REAL, &it, NULL) == -1) {
        PLOG_F("setitimer(ITIMER_REAL)");
    }
}

static void setupSignalsPreThreads(void) {
    /* Block signals which should be handled or blocked in the main thread */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGQUIT);
    sigaddset(&ss, SIGALRM);
    sigaddset(&ss, SIGPIPE);
    /* Linux/arch uses it to discover events from persistent fuzzing processes */
    sigaddset(&ss, SIGIO);
    /* Let the signal thread catch SIGCHLD */
    sigaddset(&ss, SIGCHLD);
    /* This is checked for via sigwaitinfo/sigtimedwait */
    sigaddset(&ss, SIGWINCH);
    if (sigprocmask(SIG_SETMASK, &ss, NULL) != 0) {
        PLOG_F("sigprocmask(SIG_SETMASK)");
    }

    struct sigaction sa = {
        .sa_handler = sigHandler,
        .sa_flags   = 0,
    };
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGTERM) failed");
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGINT) failed");
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGQUIT) failed");
    }
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGALRM) failed");
    }
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGCHLD) failed");
    }
    if (sigaction(SIGWINCH, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGWINCH) failed");
    }

    /* Register SA_SIGINFO handlers for fatal signals to capture faulting
     * address and instruction pointer before dying.  These are synchronous
     * (delivered on the faulting thread) so they bypass sigprocmask. */
    {
        struct sigaction sa_fatal;
        memset(&sa_fatal, 0, sizeof(sa_fatal));
        sa_fatal.sa_sigaction = fatalSignalHandler;
        sa_fatal.sa_flags     = SA_SIGINFO;
        sigemptyset(&sa_fatal.sa_mask);

        const int fatal_sigs[] = {SIGBUS, SIGSEGV, SIGABRT, SIGFPE, SIGILL};
        for (size_t i = 0; i < sizeof(fatal_sigs) / sizeof(fatal_sigs[0]); i++) {
            if (sigaction(fatal_sigs[i], &sa_fatal, NULL) == -1) {
                PLOG_F("sigaction(%s) failed", fatalSigName(fatal_sigs[i]));
            }
        }
    }
}

static void setupSignalsMainThread(void) {
    /* Unblock signals which should be handled by the main thread */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGQUIT);
    sigaddset(&ss, SIGALRM);
    sigaddset(&ss, SIGWINCH);
    if (pthread_sigmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_F("pthread_sigmask(SIG_UNBLOCK)");
    }
}

static void printSummary(honggfuzz_t* hfuzz) {
    uint64_t exec_per_sec = 0;
    uint64_t elapsed_sec  = time(NULL) - hfuzz->timing.timeStart;
    if (elapsed_sec) {
        exec_per_sec = hfuzz->cnts.mutationsCnt / elapsed_sec;
    }
    uint64_t guardNb = atomic_load_explicit(&hfuzz->feedback.covFeedbackMap->guardNb, memory_order_relaxed);
    uint64_t branch_percent_cov =
        guardNb ? ((100 * ATOMIC_GET(hfuzz->feedback.hwCnts.softCntEdge)) / guardNb) : 0;
    struct rusage usage;
    if (getrusage(RUSAGE_CHILDREN, &usage)) {
        PLOG_W("getrusage  failed");
        usage.ru_maxrss = 0;    // 0 means something went wrong with rusage
    }
#ifdef _HF_ARCH_DARWIN
    usage.ru_maxrss >>= 20;
#else
    usage.ru_maxrss >>= 10;
#endif
    LOG_I("Summary iterations:%zu time:%" PRIu64 " speed:%" PRIu64 " "
          "crashes_count:%zu timeout_count:%zu new_units_added:%zu "
          "slowest_unit_ms:%" PRId64 " guard_nb:%" PRIu64 " branch_coverage_percent:%" PRIu64 " "
          "peak_rss_mb:%lu",
        hfuzz->cnts.mutationsCnt, elapsed_sec, exec_per_sec, hfuzz->cnts.crashesCnt,
        hfuzz->cnts.timeoutedCnt, hfuzz->io.newUnitsAdded,
        hfuzz->timing.timeOfLongestUnitUSecs / 1000U, guardNb,
        branch_percent_cov, usage.ru_maxrss);
}

static void pingThreads(honggfuzz_t* hfuzz) {
    for (size_t i = 0; i < hfuzz->threads.threadsMax; i++) {
        if (pthread_kill(hfuzz->threads.threads[i], SIGCHLD) != 0 && errno != EINTR && errno != 0) {
            PLOG_W("pthread_kill(thread=%zu, SIGCHLD)", i);
        }
    }
}

static void* signalThread(void* arg) {
    honggfuzz_t* hfuzz = (honggfuzz_t*)arg;

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGCHLD);
    if (pthread_sigmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_F("Couldn't unblock SIGCHLD in the signal thread");
    }

    for (;;) {
        int sig = 0;
        errno   = 0;
        int ret = sigwait(&ss, &sig);
        if (ret == EINTR) {
            continue;
        }
        if (ret != 0 && errno == EINTR) {
            continue;
        }
        if (ret != 0) {
            PLOG_F("sigwait(SIGCHLD)");
        }
        if (fuzz_isTerminating()) {
            break;
        }
        if (sig == SIGCHLD) {
            pingThreads(hfuzz);
        }
    }

    return NULL;
}

static uint8_t mainThreadLoop(honggfuzz_t* hfuzz) {
    setupSignalsMainThread();
    setupMainThreadTimer();

    const size_t threadsTotal = hfuzz->threads.threadsMax;

    uint64_t dynamicQueuePollTime = time(NULL);
    for (;;) {
        if (hfuzz->io.dynamicInputDir && time(NULL) - dynamicQueuePollTime > _HF_SYNC_TIME) {
            LOG_D("Loading files from the dynamic input queue...");
            input_enqueueDynamicInputs(hfuzz);
            dynamicQueuePollTime = time(NULL);
        }

        if (hfuzz->display.useScreen) {
            if (ATOMIC_XCHG(clearWin, false)) {
                display_clear();
            }
            display_display(hfuzz);
        }
        if (ATOMIC_GET(sigReceived) > 0) {
            LOG_I("Signal %d (%s) received, terminating", ATOMIC_GET(sigReceived),
                strsignal(ATOMIC_GET(sigReceived)));
            break;
        }
        if (ATOMIC_GET(hfuzz->threads.threadsFinished) >= threadsTotal) {
            break;
        }
        if (hfuzz->timing.runEndTime > 0 && (time(NULL) > hfuzz->timing.runEndTime)) {
            LOG_I("Maximum run time reached, terminating");
            break;
        }
        if (hfuzz->timing.exitOnTime > 0 &&
            time(NULL) - ATOMIC_GET(hfuzz->timing.lastCovUpdate) > hfuzz->timing.exitOnTime) {
            LOG_I("No new coverage was found for the last %" PRIu64 " seconds, terminating",
                (uint64_t)hfuzz->timing.exitOnTime);
            break;
        }
        pingThreads(hfuzz);
        pause();
    }

    fuzz_setTerminating();

    for (;;) {
        if (ATOMIC_GET(hfuzz->threads.threadsFinished) >= threadsTotal) {
            break;
        }
        pingThreads(hfuzz);
        util_sleepForMSec(50); /* 50ms */
    }
    if (hfuzz->cfg.exitUponCrash && ATOMIC_GET(hfuzz->cnts.crashesCnt) > 0) {
        return hfuzz->cfg.exitCodeUponCrash;
    } else {
        return EXIT_SUCCESS;
    }
}

static const char* strYesNo(bool yes) {
    return (yes ? "true" : "false");
}

static const char* getGitVersion() {
    static char version[] = "$Id$";
    if (strlen(version) == 47) {
        version[45] = '\0';
        return &version[5];
    }
    return "UNKNOWN";
}

static const char* getGitCommitHash() {
#ifdef GIT_COMMIT_HASH
    return GIT_COMMIT_HASH;
#else
    return "unknown";
#endif
}

static const char* getGitCommitBranch() {
#ifdef GIT_COMMIT_BRANCH
    return GIT_COMMIT_BRANCH;
#else
    return "unknown";
#endif
}

static const char* getGitCommitAuthor() {
#ifdef GIT_COMMIT_AUTHOR
    return GIT_COMMIT_AUTHOR;
#else
    return "unknown";
#endif
}

static const char* getGitCommitTitle() {
#ifdef GIT_COMMIT_TITLE
    return GIT_COMMIT_TITLE;
#else
    return "unknown";
#endif
}

int main(int argc, char** argv) {
    atexit(atexitDiagnostics);

    LOG_I("Build info: commit:%s branch:'%s' author:'%s' title:'%s'",
        getGitCommitHash(), getGitCommitBranch(), getGitCommitAuthor(), getGitCommitTitle());

    /*
     * Work around CygWin/MinGW
     */
    char** myargs = (char**)util_Calloc(sizeof(char*) * (argc + 1));
    defer {
        free(myargs);
    };

    int i;
    for (i = 0U; i < argc; i++) {
        myargs[i] = argv[i];
    }
    myargs[i] = NULL;

    if (!cmdlineParse(argc, myargs, &hfuzz)) {
        LOG_F("Parsing of the cmd-line arguments failed");
    }
    hfuzz.coverageData.fd = -1;
    if (hfuzz.io.inputDir && access(hfuzz.io.inputDir, R_OK) == -1) {
        PLOG_F("Input directory '%s' is not readable", hfuzz.io.inputDir);
    }
    if (hfuzz.io.outputDir && access(hfuzz.io.outputDir, W_OK) == -1) {
        PLOG_F("Output directory '%s' is not writeable", hfuzz.io.outputDir);
    }
    if (hfuzz.cfg.minimize) {
        LOG_I("Minimization mode enabled. Setting number of threads to 1");
        hfuzz.threads.threadsMax = 1;
    }

    if (hfuzz.cfg.replay) {
        hfuzz.mutate.mutationsPerRun = 0;
        hfuzz.exe.useCustomMutator   = false;
        hfuzz.exe.useCrossover       = false;
        if (hfuzz.timing.tmOut > 0) {
            hfuzz.timing.tmOut *= 10;
        }
        if (hfuzz.feedback.dynFileMethod == _HF_DYNFILE_NONE) {
            hfuzz.feedback.dynFileMethod = _HF_DYNFILE_SOFT;
        }
        hfuzz_metrics_disable();
        LOG_I("Replay mode: mutations/crossover/metrics disabled, "
              "timeout=%ld s, dynFileMethod=0x%x",
            (long)hfuzz.timing.tmOut,
            (unsigned)hfuzz.feedback.dynFileMethod);
    }

    char tmstr[64];
    util_getLocalTime("%F.%H.%M.%S", tmstr, sizeof(tmstr), time(NULL));
    LOG_I("Start time:'%s' bin:'%s', input:'%s', output:'%s', persistent:%s, stdin:%s, "
          "mutation_rate:%u, timeout:%ld, max_runs:%zu, threads:%zu, minimize:%s, git_commit:%s",
        tmstr, hfuzz.exe.cmdline[0], hfuzz.io.inputDir,
        hfuzz.io.outputDir ? hfuzz.io.outputDir : hfuzz.io.inputDir, strYesNo(hfuzz.exe.persistent),
        strYesNo(hfuzz.exe.fuzzStdin), hfuzz.mutate.mutationsPerRun, (long)hfuzz.timing.tmOut,
        hfuzz.mutate.mutationsMax, hfuzz.threads.threadsMax, strYesNo(hfuzz.cfg.minimize),
        getGitVersion());

    sigemptyset(&hfuzz.exe.waitSigSet);
    sigaddset(&hfuzz.exe.waitSigSet, SIGIO);   /* Persistent socket data */
    sigaddset(&hfuzz.exe.waitSigSet, SIGCHLD); /* Ping from the signal thread */

    if (hfuzz.display.useScreen) {
        display_init();
    }

    if (hfuzz.socketFuzzer.enabled) {
        LOG_I("No input file corpus loaded, the external socket_fuzzer is responsible for "
              "creating the fuzz data");
        setupSocketFuzzer(&hfuzz);
    } else if (!input_init(&hfuzz)) {
        LOG_F("Couldn't load input corpus");
        exit(EXIT_FAILURE);
    }

    if (hfuzz.mutate.dictionaryFile && !input_parseDictionary(&hfuzz)) {
        LOG_F("Couldn't parse dictionary file ('%s')", hfuzz.mutate.dictionaryFile);
    }

#if defined(_HF_ARCH_LINUX) && !defined(_HF_LINUX_NO_BFD)
    /* Extract tokens from parser generator string arrays (Lemon/Bison/Yacc) */
    arch_bfdExtractStrArray(&hfuzz, "yyTokenName"); /* Lemon */
    arch_bfdExtractStrArray(&hfuzz, "yytname");     /* Bison/Yacc */
    /* Scan .rodata for other string pointer arrays */
    arch_bfdExtractRodataStrArrays(&hfuzz);
#endif

    /* Log dictionary stats after all sources have been processed */
    if (hfuzz.mutate.dictionaryCnt > 0) {
        dict_logStats(&hfuzz);
    }

    if (hfuzz.feedback.blocklistFile && !input_parseBlacklist(&hfuzz)) {
        LOG_F("Couldn't parse stackhash blocklist file ('%s')", hfuzz.feedback.blocklistFile);
    }
#define hfuzzl hfuzz.arch_linux
    if (hfuzzl.symsBlFile &&
        ((hfuzzl.symsBlCnt = files_parseSymbolFilter(hfuzzl.symsBlFile, &hfuzzl.symsBl)) == 0)) {
        LOG_F("Couldn't parse symbols blocklist file ('%s')", hfuzzl.symsBlFile);
    }

    if (hfuzzl.symsWlFile &&
        ((hfuzzl.symsWlCnt = files_parseSymbolFilter(hfuzzl.symsWlFile, &hfuzzl.symsWl)) == 0)) {
        LOG_F("Couldn't parse symbols allowlist file ('%s')", hfuzzl.symsWlFile);
    }

    if (!(hfuzz.feedback.covFeedbackMap =
                files_mapSharedMem(sizeof(feedback_t), &hfuzz.feedback.covFeedbackFd,
                    "hf-covfeedback", /* nocore= */ true, /* export= */ hfuzz.io.exportFeedback))) {
        LOG_F("files_mapSharedMem(name='hf-covfeddback', sz=%zu, dir='%s') failed",
            sizeof(feedback_t), hfuzz.io.workDir);
    }
#if defined(_HF_ARCH_LINUX) && !defined(_HF_LINUX_NO_BFD)
    arch_bfdExtractRodataStrArrays(&hfuzz);
#endif
    if (!(hfuzz.feedback.cmpFeedbackMap = files_mapSharedMem(sizeof(fuzz_data_t),
              &hfuzz.feedback.cmpFeedbackFd, "hf-cmpfeedback", /* nocore= */ true,
              /* export= */ hfuzz.io.exportFeedback))) {
        LOG_F("files_mapSharedMem(name='hf-cmpfeedback', sz=%zu, dir='%s') failed",
            sizeof(fuzz_data_t), hfuzz.io.workDir);
    }
    if (hfuzz.feedback.cmpFeedbackMap) {
#if defined(_HF_ARCH_LINUX) && !defined(_HF_LINUX_NO_BFD)
        arch_elfCollectRoValues(&hfuzz);
#endif
        for (size_t i = 0;
            i < hfuzz.mutate.dictionaryCnt && i < ARRAYSIZE(hfuzz.feedback.cmpFeedbackMap->dict);
            i++) {
            size_t len = hfuzz.mutate.dictionary[i].len;
            if (len > sizeof(hfuzz.feedback.cmpFeedbackMap->dict[i].val)) {
                len = sizeof(hfuzz.feedback.cmpFeedbackMap->dict[i].val);
            }
            memcpy(hfuzz.feedback.cmpFeedbackMap->dict[i].val, hfuzz.mutate.dictionary[i].val, len);
            hfuzz.feedback.cmpFeedbackMap->dict[i].len = len;
        }
        hfuzz.feedback.cmpFeedbackMap->dictCnt =
            HF_MIN(hfuzz.mutate.dictionaryCnt, ARRAYSIZE(hfuzz.feedback.cmpFeedbackMap->dict));
        hfuzz.feedback.cmpFeedbackMap->dictStaticCnt = hfuzz.feedback.cmpFeedbackMap->dictCnt;
    }
    /* Stats file. */
    if (hfuzz.io.statsFileName) {
        hfuzz.io.statsFileFd =
            TEMP_FAILURE_RETRY(open(hfuzz.io.statsFileName, O_CREAT | O_RDWR | O_TRUNC, 0640));

        if (hfuzz.io.statsFileFd == -1) {
            PLOG_F("Couldn't open statsfile open('%s')", hfuzz.io.statsFileName);
        } else {
            dprintf(hfuzz.io.statsFileFd,
                "# unix_time, last_cov_update, total_exec, exec_per_sec, "
                "crashes, unique_crashes, hangs, edge_cov, block_cov, corpus_count\n");
        }
    }

    setupRLimits();
    setupSignalsPreThreads();

    /* Initialize metrics logging BEFORE starting fuzz threads (so coverage registration works) */
    hfuzz_metrics_session_init(hfuzz.exe.cmdline[0], argc, myargs);

    hfuzz_metrics_register_coverage_feedback(
        hfuzz.feedback.covFeedbackMap->pcGuardMap,
        &hfuzz.feedback.covFeedbackMap->guardNb);

    fuzz_threadsStart(&hfuzz);

    pthread_t sigthread;
    if (!subproc_runThread(&hfuzz, &sigthread, signalThread, /* joinable= */ false)) {
        LOG_F("Couldn't start the signal thread");
    }

    uint8_t exitcode = mainThreadLoop(&hfuzz);

    /* Clean-up global buffers */
    if (hfuzz.feedback.blocklist) {
        free(hfuzz.feedback.blocklist);
    }
#if defined(_HF_ARCH_LINUX)
    if (hfuzz.arch_linux.symsBl) {
        free(hfuzz.arch_linux.symsBl);
    }
    if (hfuzz.arch_linux.symsWl) {
        free(hfuzz.arch_linux.symsWl);
    }
#elif defined(_HF_ARCH_NETBSD)
    if (hfuzz.arch_netbsd.symsBl) {
        free(hfuzz.arch_netbsd.symsBl);
    }
    if (hfuzz.arch_netbsd.symsWl) {
        free(hfuzz.arch_netbsd.symsWl);
    }
#endif
    if (hfuzz.socketFuzzer.enabled) {
        cleanupSocketFuzzer();
    }
    /* Stats file. */
    if (hfuzz.io.statsFileName) {
        close(hfuzz.io.statsFileFd);
    }

    printSummary(&hfuzz);

    /* Finalize metrics logging (optional - weak symbol, no-op if not overridden) */
    {
        uint64_t elapsed_sec = time(NULL) - hfuzz.timing.timeStart;
        struct rusage usage;
        uint64_t memory_peak_mb = 0;
        if (getrusage(RUSAGE_CHILDREN, &usage) == 0) {
#ifdef _HF_ARCH_DARWIN
            memory_peak_mb = usage.ru_maxrss >> 20;
#else
            memory_peak_mb = usage.ru_maxrss >> 10;
#endif
        }
        /* Log full coverage report before session end */
        if (hfuzz.feedback.covFeedbackMap) {
            uint64_t guardNb = atomic_load_explicit(
                &hfuzz.feedback.covFeedbackMap->guardNb, memory_order_relaxed);

            /* Generate output path for JSON coverage report if coverage dir is set */
            char coverage_path[PATH_MAX] = {0};
            if (hfuzz.io.covDirNew) {
                int cp = snprintf(coverage_path, sizeof(coverage_path),
                                  "%s/coverage_report.json", hfuzz.io.covDirNew);
                if (cp < 0 || (size_t)cp >= sizeof(coverage_path)) {
                    coverage_path[0] = '\0';
                }
            }

            hfuzz_metrics_log_full_coverage_report(
                hfuzz.feedback.covFeedbackMap->pcGuardMap,
                guardNb,
                coverage_path[0] ? coverage_path : NULL);
        }

        if (hfuzz.coverageData.fd >= 0) {
            uint64_t guardNbFinal = atomic_load_explicit(&hfuzz.feedback.covFeedbackMap->guardNb, memory_order_relaxed);
            uint64_t fileCntFinal = (uint64_t)ATOMIC_GET(hfuzz.coverageData.entryCnt);
            if (!fuzz_coverageDataFinalizeHeader(hfuzz.coverageData.fd, guardNbFinal, fileCntFinal)) {
                PLOG_W("Failed to finalize coverage_data.bin header");
            }
            close(hfuzz.coverageData.fd);
            hfuzz.coverageData.fd = -1;
            LOG_I("Wrote %zu coverage data entries to coverage_data.bin", (size_t)fileCntFinal);
        }

        if (ATOMIC_GET(hfuzz.coverageRequired.requiredFileCnt) > 0 && hfuzz.io.covDirNew) {
            char req_path[PATH_MAX];
            int n = snprintf(req_path, sizeof(req_path), "%s/coverage_required.json",
                             hfuzz.io.covDirNew);
            if (n < 0 || (size_t)n >= sizeof(req_path)) {
                LOG_E("coverage_required.json path too long (covDirNew='%s')", hfuzz.io.covDirNew);
            } else {
                size_t cnt = ATOMIC_GET(hfuzz.coverageRequired.requiredFileCnt);
                if (!hfuzz_write_coverage_required_json) {
                    LOG_E("coverage_required.json writer not linked (missing RapidJSON?)");
                } else if (hfuzz_write_coverage_required_json(
                               req_path, (const char* const*)hfuzz.coverageRequired.requiredFiles,
                               cnt) != 0) {
                    LOG_E("Failed to write coverage_required.json");
                } else {
                    LOG_I("Wrote %zu coverage-required files to %s", cnt, req_path);
                }
            }
        }

        const char* status = (hfuzz.cfg.exitUponCrash && ATOMIC_GET(hfuzz.cnts.crashesCnt) > 0)
                             ? "crashed" : "completed";
        hfuzz_metrics_session_end(status,
                                   hfuzz.cnts.mutationsCnt,
                                   hfuzz.cnts.crashesCnt,
                                   hfuzz.cnts.timeoutedCnt,
                                   elapsed_sec,
                                   memory_peak_mb);
    }

    return exitcode;
}
