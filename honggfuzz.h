/*
 *
 * honggfuzz - core structures and macros
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

#ifndef _HF_HONGGFUZZ_H_
#define _HF_HONGGFUZZ_H_

#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <time.h>

#include "libhfcommon/util.h"

#define PROG_NAME    "honggfuzz"
#define PROG_VERSION "2.6"

/* Name of the template which will be replaced with the proper name of the file */
#define _HF_FILE_PLACEHOLDER "___FILE___"

/* Default name of the report created with some architectures */
#define _HF_REPORT_FILE "HONGGFUZZ.REPORT.TXT"

/* Default stack-size of created threads. */
#define _HF_PTHREAD_STACKSIZE (1024ULL * 1024ULL * 2ULL) /* 2MB */

/* Name of envvar which indicates sequential number of fuzzer */
#define _HF_THREAD_NO_ENV "HFUZZ_THREAD_NO"

/* Name of envvar which indicates that the netDriver should be used */
#define _HF_THREAD_NETDRIVER_ENV "HFUZZ_USE_NETDRIVER"

/* Name of envvar which indicates honggfuzz's log level in use */
#define _HF_LOG_LEVEL_ENV "HFUZZ_LOG_LEVEL"

/* Number of crash verifier iterations before tag crash as stable */
#define _HF_VERIFIER_ITER 5

/* Size (in bytes) for report data to be stored in stack before written to file */
#define _HF_REPORT_SIZE 32768

/* Perf bitmap size */
#define _HF_PERF_BITMAP_SIZE_16M   (1024U * 1024U * 16U)
#define _HF_PERF_BITMAP_BITSZ_MASK 0x7FFFFFFULL
/* Maximum number of PC guards (=trace-pc-guard) we support */
#define _HF_PC_GUARD_MAX (1024ULL * 1024ULL * 128ULL)

/* Maximum size of the input file in bytes (32 MiB) */
#define _HF_INPUT_MAX_SIZE (1024ULL * 1024ULL * 32ULL)

/* Default maximum size of produced inputs */
#define _HF_INPUT_DEFAULT_SIZE (1024ULL * 8)

/* Time (seconds) between checking dynamic input directory to import files */
#define _HF_SYNC_TIME 1

/* Per-thread bitmap */
#define _HF_PERTHREAD_BITMAP_FD 1018
/* FD used to report back used int/str constants from the fuzzed process */
#define _HF_CMP_BITMAP_FD 1019
/* FD used to log inside the child process */
#define _HF_LOG_FD 1020
/* FD used to represent the input file */
#define _HF_INPUT_FD 1021
/* FD used to pass coverage feedback from the fuzzed process */
#define _HF_COV_BITMAP_FD 1022
#define _HF_BITMAP_FD     _HF_COV_BITMAP_FD /* Old name for _HF_COV_BITMAP_FD */
/* FD used to pass data to a persistent process */
#define _HF_PERSISTENT_FD 1023

/* Input file as a string */
#define _HF_INPUT_FILE_PATH "/dev/fd/" HF_XSTR(_HF_INPUT_FD)

/* Maximum number of supported execve() args */
#define _HF_ARGS_MAX 2048

/* Message indicating that the fuzzed process is ready for new data */
static const uint8_t HFReadyTag = 'R';

/* Maximum number of active fuzzing threads */
#define _HF_THREAD_MAX 1024U

/* Persistent-binary signature - if found within file, it means it's a persistent mode binary */
#define _HF_PERSISTENT_SIG "\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"
/* HF NetDriver signature - if found within file, it means it's a NetDriver-based binary */
#define _HF_NETDRIVER_SIG "\x01_LIBHFUZZ_NETDRIVER_BINARY_SIGNATURE_\x02\xFF"

/* printf() nonmonetary separator. According to MacOSX's man it's supported there as well */
#define _HF_NONMON_SEP "'"

typedef enum {
    _HF_DYNFILE_NONE         = 0x0,
    _HF_DYNFILE_INSTR_COUNT  = 0x1,
    _HF_DYNFILE_BRANCH_COUNT = 0x2,
    _HF_DYNFILE_BTS_EDGE     = 0x10,
    _HF_DYNFILE_IPT_BLOCK    = 0x20,
    _HF_DYNFILE_SOFT         = 0x40,
} dynFileMethod_t;

typedef struct {
    uint64_t cpuInstrCnt;
    uint64_t cpuBranchCnt;
    uint64_t bbCnt;
    uint64_t newBBCnt;
    uint64_t softCntPc;
    uint64_t softCntEdge;
    uint64_t softCntCmp;        /* Unbounded: CMP solving progress (trace_cmp improvements) */
    uint64_t softCntEdgeBucket; /* Unbounded: edge count bucket increases (less meaningful) */
} hwcnt_t;

typedef enum {
    _HF_STATE_UNSET = 0,
    _HF_STATE_STATIC,
    _HF_STATE_DYNAMIC_DRY_RUN,
    _HF_STATE_DYNAMIC_MAIN,
    _HF_STATE_DYNAMIC_MINIMIZE,
    _HF_STATE_REPLAY,
} fuzzState_t;

typedef enum {
    HF_MAYBE = -1,
    HF_NO    = 0,
    HF_YES   = 1,
} tristate_t;

struct _dynfile_t {
    size_t             size;
    uint64_t           cov[4];
    size_t             idx;
    int                fd;
    uint64_t           timeExecUSecs;
    time_t             timeAdded; /* When this input was added to corpus */
    char               path[PATH_MAX];
    struct _dynfile_t* src;
    uint32_t           refs;
    uint32_t           newEdges;    /* New edges discovered when added */
    uint32_t           depth;       /* Mutation depth from seed */
    uint64_t           stackDepth;  /* Max stack depth observed */
    uint64_t           pathHash;    /* Hash of execution path for diversity */
    uint32_t           selectCnt;   /* Times this input was selected */
    uint32_t           cmpProgress; /* Comparison progress score */
    uint16_t           rareEdgeCnt; /* Count of rare edges this input hits */
    uint16_t           mismatchRefs; /* Descendants that caused NEW mismatches (diff fuzzing) */
    uint16_t           dupCrashRefs; /* Descendants that caused DUPLICATE crashes (saturation) */
    uint8_t            complexity;  /* Input structural complexity score (0-255) */
    uint8_t            entropy;     /* Cached entropy score (0-100) */
    uint64_t           energy;      /* Cached energy value for selection */
    time_t             energyTime;  /* When energy was last computed */
    fuzzState_t        phase;
    bool               timedout;
    uint8_t*           data;
    bool               imported;
    TAILQ_ENTRY(_dynfile_t) pointers;
};

typedef struct _dynfile_t dynfile_t;

struct strings_t {
    size_t len;
    TAILQ_ENTRY(strings_t) pointers;
    char s[];
};

/* Cache-line padded counters to avoid false sharing between threads */
#define _HF_CACHE_LINE_SZ 64
typedef struct {
    uint64_t val;
    uint8_t  _pad[_HF_CACHE_LINE_SZ - sizeof(uint64_t)];
} __attribute__((aligned(_HF_CACHE_LINE_SZ))) cntCacheLine_t;

typedef struct {
    size_t  val;
    uint8_t _pad[_HF_CACHE_LINE_SZ - sizeof(size_t)];
} __attribute__((aligned(_HF_CACHE_LINE_SZ))) sizeCacheLine_t;

typedef struct {
    bool    val;
    uint8_t _pad[_HF_CACHE_LINE_SZ - sizeof(bool)];
} __attribute__((aligned(_HF_CACHE_LINE_SZ))) boolCacheLine_t;

/* Module tracking entry for PC guard leak prevention (in shared memory) */
#define _HF_MAX_TRACKED_MODULES 4096
typedef struct {
    uint64_t pathHash;
    uint32_t baseGuard;
    uint32_t guardCount;
} trackedModule_t;

typedef struct {
    uint8_t  pcGuardMap[_HF_PC_GUARD_MAX];
    uint8_t  bbMapPc[_HF_PERF_BITMAP_SIZE_16M];
    uint32_t bbMapCmp[_HF_PERF_BITMAP_SIZE_16M];
    _Atomic uint64_t guardNb;
    /* Per-thread counters - cache-line padded to avoid false sharing */
    cntCacheLine_t  pidNewPC[_HF_THREAD_MAX];
    cntCacheLine_t  pidNewEdge[_HF_THREAD_MAX];
    cntCacheLine_t  pidNewCmp[_HF_THREAD_MAX];        /* CMP solving: trace_cmp bit improvements */
    cntCacheLine_t  pidEdgeBucketInc[_HF_THREAD_MAX]; /* Edge frequency: bucket increases (unbounded) */
    cntCacheLine_t  pidTotalPC[_HF_THREAD_MAX];
    cntCacheLine_t  pidTotalEdge[_HF_THREAD_MAX];
    cntCacheLine_t  pidTotalCmp[_HF_THREAD_MAX];
    sizeCacheLine_t maxStackDepth[_HF_THREAD_MAX];
    sizeCacheLine_t pidLastStackDepth[_HF_THREAD_MAX];
    boolCacheLine_t pidNewStackDepth[_HF_THREAD_MAX];
    cntCacheLine_t  pidPathHash[_HF_THREAD_MAX];    /* Execution path hash */
    cntCacheLine_t  pidCmpProgress[_HF_THREAD_MAX]; /* CMP solving progress */
    cntCacheLine_t  pidRareEdgeCnt[_HF_THREAD_MAX]; /* Rare edges hit this run */
    /* Global edge frequency tracking - indexed by (guard % size) */
    uint8_t edgeHitCnt[65536];
    /* Module tracking for PC guard leak prevention - survives across process spawns */
    _Atomic uint32_t moduleRegistrationLock;  /* Simple spinlock for module registration */
    _Atomic uint32_t trackedModuleCount;
    trackedModule_t trackedModules[_HF_MAX_TRACKED_MODULES];
    /* Mutation health counters -- per-thread slots (same pattern as pidNewPC etc.)
       to avoid contention.  Each persistent child writes only to its own slot
       (indexed by my_thread_no).  Parent sums across all slots for metrics. */
    cntCacheLine_t pidProtoParseCallsCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidProtoParseSuccessesCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidCustomMutatorCallsCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidCustomMutatorSuccessesCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidInputsTruncatedCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidKutatorMutateCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidKutatorCrossOverCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidKutatorParseSuccessCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidKutatorParseFailCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidKutatorEncodeOverflow[_HF_THREAD_MAX];
    cntCacheLine_t pidKutatorNoCandidates[_HF_THREAD_MAX];
#define _HF_KUTATOR_KIND_MAX   32
#define _HF_KUTATOR_NAME_MAX  32
    _Atomic uint32_t kutatorKindNum;
    _Atomic uint8_t  kutatorKindNameReady[_HF_KUTATOR_KIND_MAX];
    char           kutatorKindNames[_HF_KUTATOR_KIND_MAX][_HF_KUTATOR_NAME_MAX];
    cntCacheLine_t pidKutatorKind[_HF_KUTATOR_KIND_MAX][_HF_THREAD_MAX];
    cntCacheLine_t pidElfFixupOkCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidExecFailCnt[_HF_THREAD_MAX];
    cntCacheLine_t pidVerifyCnt[_HF_THREAD_MAX];
} feedback_t;

typedef struct {
    uint8_t  val[64];
    uint32_t len;
} dict_entry_t;

typedef struct {
    dict_entry_t dict[1024 * 32];
    uint32_t     dictCnt;
    uint32_t     dictStaticCnt;
    uint32_t     ro32[1024 * 128];
    uint32_t     ro32Cnt;
    uint64_t     ro64[1024 * 128];
    uint32_t     ro64Cnt;
} fuzz_data_t;

typedef struct {
    struct {
        size_t    threadsMax;
        size_t    threadsFinished;
        uint32_t  threadsActiveCnt;
        pthread_t mainThread;
        pid_t     mainPid;
        uint32_t  pinThreadToCPUs;
        pthread_t threads[_HF_THREAD_MAX];
    } threads;
    struct {
        const char* inputDir;
        const char* outputDir;
        DIR*        inputDirPtr;
        size_t      fileCnt;
        size_t      testedFileCnt;
        const char* fileExtn;
        size_t      maxFileSz;
        size_t      minFileSz;
        size_t      newUnitsAdded;
        char        workDir[PATH_MAX];
        const char* crashDir;
        const char* covDirNew;
        bool        saveUnique;
        bool        saveSmaller;
        size_t      dynfileqMaxSz;
        size_t      dynfileqCnt;
        size_t      dynfileqId;
        dynfile_t*  dynfileqCurrent;
        dynfile_t*  dynfileq2Current;
        dynfile_t*  dynfileqDiverseCurrent;
        TAILQ_HEAD(dyns_t, _dynfile_t) dynfileq;
        bool        exportFeedback;
        const char* dynamicInputDir;
        const char* statsFileName;
        int         statsFileFd;
    } io;
    struct {
        int                argc;
        const char* const* cmdline;
        bool               nullifyStdio;
        bool               fuzzStdin;
        const char*        externalCommand;
        const char*        postExternalCommand;
        const char*        feedbackMutateCommand;
        bool               netDriver;
        bool               persistent;
        bool               useCustomMutator;
        uint64_t           asLimit;
        uint64_t           rssLimit;
        uint64_t           dataLimit;
        uint64_t           coreLimit;
        uint64_t           stackLimit;
        bool               clearEnv;
        char*              env_ptrs[128];
        char               env_vals[128][4096];
        sigset_t           waitSigSet;
    } exe;
    struct {
        time_t  timeStart;
        time_t  runEndTime;
        time_t  tmOut;
        time_t  lastCovUpdate;
        time_t  exitOnTime;
        int64_t timeOfLongestUnitUSecs;
        bool    tmoutVTALRM;
    } timing;
    struct {
        struct {
            uint8_t val[512];
            size_t  len;
        } dictionary[8192];
        size_t      dictionaryCnt;
        const char* dictionaryFile;
        size_t      mutationsMax;
        unsigned    mutationsPerRun;
        size_t      maxInputSz;
        /* Mutation effectiveness tracking */
        struct {
            uint64_t tries;     /* Number of times this tier was used */
            uint64_t successes; /* Number of times it led to new coverage */
        } stats[4];             /* 0=data, 1=arith, 2=splice, 3=other */
        uint64_t protoRoundCnt;   /* Rounds where format_override was proto/flatbuf */
        uint64_t protoScanOkCnt;  /* proto_scan_fields returned >= 1 field */
        uint64_t totalRoundCnt;   /* Total mangle_mangleContent calls */
    } mutate;
    struct {
        bool    useScreen;
        char    cmdline_txt[65];
        int64_t lastDisplayUSecs;
    } display;
    struct {
        bool        useVerifier;
        bool        exitUponCrash;
        uint8_t     exitCodeUponCrash;
        const char* reportFile;
        size_t      dynFileIterExpire;
        bool        only_printable;
        bool        minimize;
        bool        replay;
        bool        switchingToFDM;
    } cfg;
    struct {
        bool enable;
        bool del_report;
    } sanitizer;
    struct {
        fuzzState_t     state;
        feedback_t*     covFeedbackMap;
        int             covFeedbackFd;
        fuzz_data_t*    cmpFeedbackMap;
        int             cmpFeedbackFd;
        const char*     blocklistFile;
        uint64_t*       blocklist;
        size_t          blocklistCnt;
        bool            skipFeedbackOnTimeout;
        uint64_t        maxCov[4];
        dynFileMethod_t dynFileMethod;
        hwcnt_t         hwCnts;
        uint64_t        uniquePaths; /* Count of unique execution paths seen */
    } feedback;
    struct {
        size_t mutationsCnt;
        size_t crashesCnt;
        size_t uniqueCrashesCnt;
        size_t verifiedCrashesCnt;
        size_t blCrashesCnt;
        size_t timeoutedCnt;
        /* Differential fuzzing metrics */
        size_t diffFuzzSelectionIters;    /* Total selection loop iterations */
        size_t diffFuzzPhase2Fallbacks;   /* Times we fell back to phase 2 selection */
        size_t diffFuzzSaturatedLineages; /* Lineages that became saturated */
        size_t diffFuzzFertileBoosts;     /* Times we boosted a fertile lineage */
        /* Power scheduling / decay metrics */
        size_t noveltyDecayApplied;       /* Times novelty decay reduced energy */
        size_t freshInputBoosts;          /* Times <60s freshness boost applied */
        size_t staleInputPenalties;       /* Times >60min no-children penalty applied */
        size_t diminishingReturnsPenalties; /* Times selectCnt>100 penalty applied */
        size_t depthPenalties;            /* Times depth>8 penalty applied */
        uint64_t energyMin;               /* Lowest energy calculated (track extremes) */
        uint64_t energyMax;               /* Highest energy calculated */
        uint64_t energySum;               /* Sum of all energies (for average) */
        size_t energyCount;               /* Count of energy calculations */
        /* Execution time metrics */
        uint64_t execTimeSum;             /* Sum of execution times in usecs */
        uint64_t execTimeMax;             /* Slowest single execution in usecs */
        size_t execTimeSlowCnt;           /* Executions > 10x average (sampled) */
        /* Mutation effectiveness metrics */
        size_t mutationsWithNewCov;       /* Mutations that discovered new coverage */
        size_t mutationsWithoutNewCov;    /* Mutations that added nothing new */
        /* Corpus health metrics */
        size_t corpusQueueWraps;          /* Times we wrapped around corpus queue */
        uint32_t corpusMaxDepth;          /* Deepest mutation depth seen */
        size_t explorationModeSelections; /* Random selections in exploration mode (stagnation >3h) */
        /* Coverage progress metrics */
        uint64_t lastNewCovTime;          /* Timestamp of last new coverage (secs) */
        uint64_t lastCovEdgeCount;        /* Edge count at last check (for velocity) */
        uint64_t lastCrashTime;           /* Timestamp of last unique crash/mismatch */
        size_t corpusSizeAtLastLog;       /* Corpus size at last log (for growth rate) */
        /* Sanity check counters (should all be 0 or very low) */
        size_t emptyQueueSelections;      /* Selected from empty queue */
        size_t forkFailures;              /* Fork syscall failures */
        size_t rssKilledCnt;             /* Children killed for exceeding RSS limits */
        size_t persistentResets;          /* Persistent mode resets */
        size_t fileIOErrors;              /* File read/write failures */
        size_t inputsTruncatedTooLarge;    /* Inputs truncated because they exceeded maxFileSz */
    } cnts;
    struct {
        bool enabled;
        int  serverSocket;
        int  clientSocket;
    } socketFuzzer;
    struct {
        pthread_rwlock_t dynfileq;
        pthread_mutex_t  feedback;
        pthread_mutex_t  report;
        pthread_mutex_t  state;
        pthread_mutex_t  input;
        pthread_mutex_t  timing;
    } mutex;

    /* For the Linux code */
    struct {
        int         exeFd;
        uint64_t    dynamicCutOffAddr;
        bool        disableRandomization;
        void*       ignoreAddr;
        const char* symsBlFile;
        char**      symsBl;
        size_t      symsBlCnt;
        const char* symsWlFile;
        char**      symsWl;
        size_t      symsWlCnt;
        uintptr_t   cloneFlags;
        tristate_t  useNetNs;
        bool        kernelOnly;
        bool        useClone;
    } arch_linux;
    /* For the NetBSD code */
    struct {
        void*       ignoreAddr;
        const char* symsBlFile;
        char**      symsBl;
        size_t      symsBlCnt;
        const char* symsWlFile;
        char**      symsWl;
        size_t      symsWlCnt;
    } arch_netbsd;
} honggfuzz_t;

typedef enum {
    _HF_RS_UNKNOWN                   = 0,
    _HF_RS_WAITING_FOR_INITIAL_READY = 1,
    _HF_RS_WAITING_FOR_READY         = 2,
    _HF_RS_SEND_DATA                 = 3,
} runState_t;

typedef struct {
    honggfuzz_t* global;
    pid_t        pid;
    int64_t      timeStartedUSecs;
    char         crashFileName[PATH_MAX];
    uint64_t     pc;
    uint64_t     backtrace;
    uint64_t     access;
    int          exception;
    char         report[_HF_REPORT_SIZE];
    bool         mainWorker;
    unsigned     mutationsPerRun;
    dynfile_t*   dynfile;
    bool         staticFileTryMore;
    uint32_t     fuzzNo;
    int          persistentSock;
    runState_t   runState;
    bool         tmOutSignaled;
    int          rssExceedCount;    /* Consecutive RSS-over-limit checks (debounce) */
    char*        args[_HF_ARGS_MAX + 1];
    int          perThreadCovFeedbackFd;
    unsigned     triesLeft;
    dynfile_t*   current;
    hwcnt_t      hwCnts;
    uint8_t      mutationTiers; /* Bitmap of mutation tiers used this run */

    /* Deferred metrics snapshot: filled under dynfileq rwlock,
       flushed after release to avoid blocking all fuzzer threads on
       ClickHouse network I/O during startup. */
    bool         pendingStatsLog;
    struct {
        uint64_t mutationsCnt, softCntPc, softCntEdge, softCntCmp, softCntEdgeBucket;
        uint64_t total;
        float    repeatPct, highPct, lowPct, phase2Pct;
        uint64_t avgEnergy;
        float    avgIters;
        uint64_t maxIters, eMin, eMax;
        uint64_t noveltyDecay, freshBoost, stalePenalty, diminishing, depthPenalty;
        uint64_t corpusSize, globalAvgEnergy;
        uint64_t avgExecTime, execTimeMax, execTimeSlow;
        float    hitRate;
        uint64_t plateauSecs, queueWraps;
        uint32_t maxDepth;
        uint64_t uniqueCrashes, totalCrashes, timeouts;
        uint64_t fertileBoosts, saturatedLineages, exploreSelects;
        uint64_t secsSinceCrash, stagnationSecs, corpusGrowth;
        uint64_t inputsTruncatedTooLarge;
    } statsSnapshot;

    struct {
        /* For Linux code */
        uint8_t* perfMmapBuf;
        uint8_t* perfMmapAux;
        int      cpuInstrFd;
        int      cpuBranchFd;
        int      cpuIptBtsFd;
    } arch_linux;
} run_t;

#endif
