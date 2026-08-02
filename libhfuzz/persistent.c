#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfuzz/fetch.h"
#include "libhfuzz/instrument.h"
#include "libhfuzz/libhfuzz.h"
#include "libhfuzz/performance.h"

__attribute__((weak)) int LLVMFuzzerInitialize(int* argc, char*** argv);

/* Simple xorshift32 PRNG for in-process mutation */
static uint32_t hf_rng_state = 0;
static uint32_t hf_rand(void) {
    uint32_t x = hf_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    hf_rng_state = x;
    return x;
}

/*
 * Real LLVMFuzzerMutate implementation for honggfuzz.
 *
 * kutator's Mutator calls this for scalar field mutations
 * (int32, int64, float, double, string bytes).  The old no-op stub meant
 * all scalar values were returned unchanged -- now we actually mutate them.
 * Non-weak so it overrides the weak fallback in libfuzzer_mutator.cc.
 */
size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize) {
    if (Size == 0) return 0;
    if (hf_rng_state == 0) {
        hf_rng_state = (uint32_t)getpid() ^ 0xdeadbeef;
    }

    uint32_t r = hf_rand();
    switch (r & 3) {
        case 0: {
            size_t pos = hf_rand() % Size;
            Data[pos] ^= 1u << (hf_rand() & 7);
            break;
        }
        case 1: {
            size_t pos = hf_rand() % Size;
            Data[pos] = (uint8_t)hf_rand();
            break;
        }
        case 2:
            if (Size < MaxSize) {
                size_t pos = hf_rand() % (Size + 1);
                memmove(Data + pos + 1, Data + pos, Size - pos);
                Data[pos] = (uint8_t)hf_rand();
                return Size + 1;
            }
            Data[hf_rand() % Size] ^= 1u << (hf_rand() & 7);
            break;
        case 3:
            if (Size > 1) {
                size_t pos = hf_rand() % Size;
                memmove(Data + pos, Data + pos + 1, Size - pos - 1);
                return Size - 1;
            }
            Data[0] = (uint8_t)hf_rand();
            break;
    }
    return Size;
}

__attribute__((weak)) int LLVMFuzzerTestOneInput(
    const uint8_t* buf HF_ATTR_UNUSED, size_t len HF_ATTR_UNUSED) {
    LOG_F("Define 'int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len)' in your "
          "code to make it work");
    return 0;
}

/*
 * Weak reference to LLVMFuzzerCustomMutator.
 *
 * Solfuzz harnesses are expected to provide this (via
 * DEFINE_BINARY_PROTO_FUZZER or a hand-written custom mutator). If it is
 * missing, startup warns and mutation falls back to generic byte-level
 * mutation instead of aborting.
 */
__attribute__((weak)) size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, unsigned int seed);

/*
 * Weak reference to LLVMFuzzerCustomCrossOver.
 *
 * Schema-aware crossover: takes two protobuf inputs (destination + donor),
 * applies field-level crossover (CrossoverCopy / CrossoverClone via
 * protobuf-kutator), and writes the result to out.  The persistent loop
 * maintains a ring buffer of recent inputs as donors.
 */
__attribute__((weak)) size_t LLVMFuzzerCustomCrossOver(
    const uint8_t* data1, size_t size1,
    const uint8_t* data2, size_t size2,
    uint8_t* out, size_t max_out_size, unsigned int seed);

/* Set to true when running from file (replay mode), not under honggfuzz.
   Exported so harness code (e.g. Rust FFI) can detect replay vs fuzzing. */
bool hf_replay_mode = false;

static uint8_t  hf_mut_buf[_HF_INPUT_MAX_SIZE];
static uint8_t  hf_xover_buf[_HF_INPUT_MAX_SIZE];
static uint32_t hf_mut_counter = 0;

/* Shared coverage feedback struct (mmap'd, visible to parent for metrics).
   my_thread_no indexes our per-thread slot.  Both from instrument.c. */
extern feedback_t* globalCovFeedback;
extern uint32_t    my_thread_no;

void HF_ITER(const uint8_t** buf_ptr, size_t* len_ptr) {
    /* The libFuzzer driver resets the per-thread guard map in HonggfuzzRunOneInput();
     * this manual API has no equivalent hook, so it has to happen here.  Without it the
     * map accumulates across iterations and anything reading it per input -- replay's
     * coverage check, and the per-file records covdir_new writes to coverage_data.bin
     * -- credits this input with guards that earlier ones reached.
     *
     * After the fetch, never before it.  HonggfuzzFetchData() writes HFReadyTag first,
     * which is what tells the parent the previous input is finished and its map is
     * ready to read; resetting ahead of that wipes the results the parent is about to
     * collect.  By the time the call returns the parent has sent the next input, so it
     * is done with the previous one and the map can be cleared for this one.
     *
     * Not folded into HonggfuzzFetchData() itself: the driver loop calls that before
     * running the custom mutator and then resets again in RunOneInput, so a reset there
     * would be redundant -- and the redundant pass is a full bzero of the guard map
     * whenever the touched-list has overflowed, on the hot path. */
    HonggfuzzFetchData(buf_ptr, len_ptr);
    instrumentResetLocalCovFeedback();
}

/* Proto parse counter accessors (defined in kutator's libfuzzer_macro.cc,
   linked into the same process).  We accumulate deltas into shared memory so the
   honggfuzz parent can read the aggregate across all child processes. */
__attribute__((weak)) uint64_t solfuzz_proto_parse_calls(void);
__attribute__((weak)) uint64_t solfuzz_proto_parse_successes(void);
__attribute__((weak)) uint64_t solfuzz_kutator_mutate_calls(void);
__attribute__((weak)) uint64_t solfuzz_kutator_crossover_calls(void);
__attribute__((weak)) uint64_t solfuzz_kutator_parse_success_calls(void);
__attribute__((weak)) uint64_t solfuzz_kutator_parse_fail_calls(void);
__attribute__((weak)) uint64_t solfuzz_kutator_encode_overflow(void);
__attribute__((weak)) uint64_t solfuzz_kutator_no_candidates(void);
__attribute__((weak)) uint32_t solfuzz_kutator_kind_num(void);
__attribute__((weak)) uint64_t solfuzz_kutator_kind_count(uint32_t idx);
__attribute__((weak)) const char* solfuzz_kutator_kind_name(uint32_t idx);
__attribute__((weak)) uint64_t solfuzz_exec_fail_calls(void);
__attribute__((weak)) uint64_t solfuzz_verify_calls(void);
__attribute__((weak)) uint64_t solfuzz_harness_reject_calls(void);

extern const char* const LIBHFUZZ_module_memorycmp;
extern const char* const LIBHFUZZ_module_instrument;
static void              HonggfuzzRunOneInput(const uint8_t* buf, size_t len) {
    instrumentResetLocalCovFeedback();
    instrumentResetStackDepth();
    int ret = LLVMFuzzerTestOneInput(buf, len);
    if (ret == -1) {
        /* libFuzzer convention: -1 means "reject / skip this input".
           Don't record coverage -- the target chose not to process it
           (e.g. input too small).  This avoids killing the persistent
           child on every rejected mutation. */
        return;
    }
    if (ret != 0) {
        LOG_D("Dereferenced: %s, %s", LIBHFUZZ_module_memorycmp, LIBHFUZZ_module_instrument);
        LOG_F("LLVMFuzzerTestOneInput() returned '%d' instead of '0'", ret);
    }
    instrument8BitCountersCount();
    instrumentCheckStackDepth();

    if (solfuzz_proto_parse_calls) {
        ATOMIC_SET(globalCovFeedback->pidProtoParseCallsCnt[my_thread_no].val,
            solfuzz_proto_parse_calls());
    }
    if (solfuzz_proto_parse_successes) {
        ATOMIC_SET(globalCovFeedback->pidProtoParseSuccessesCnt[my_thread_no].val,
            solfuzz_proto_parse_successes());
    }
    if (solfuzz_kutator_mutate_calls) {
        ATOMIC_SET(globalCovFeedback->pidKutatorMutateCnt[my_thread_no].val,
            solfuzz_kutator_mutate_calls());
    }
    if (solfuzz_kutator_crossover_calls) {
        ATOMIC_SET(globalCovFeedback->pidKutatorCrossOverCnt[my_thread_no].val,
            solfuzz_kutator_crossover_calls());
    }
    if (solfuzz_kutator_parse_success_calls) {
        ATOMIC_SET(globalCovFeedback->pidKutatorParseSuccessCnt[my_thread_no].val,
            solfuzz_kutator_parse_success_calls());
    }
    if (solfuzz_kutator_parse_fail_calls) {
        ATOMIC_SET(globalCovFeedback->pidKutatorParseFailCnt[my_thread_no].val,
            solfuzz_kutator_parse_fail_calls());
    }
    if (solfuzz_kutator_encode_overflow) {
        ATOMIC_SET(globalCovFeedback->pidKutatorEncodeOverflow[my_thread_no].val,
            solfuzz_kutator_encode_overflow());
    }
    if (solfuzz_kutator_no_candidates) {
        ATOMIC_SET(globalCovFeedback->pidKutatorNoCandidates[my_thread_no].val,
            solfuzz_kutator_no_candidates());
    }
    if (solfuzz_kutator_kind_num && solfuzz_kutator_kind_count) {
        uint32_t n = solfuzz_kutator_kind_num();
        if (n > _HF_KUTATOR_KIND_MAX) n = _HF_KUTATOR_KIND_MAX;
        atomic_store_explicit(&globalCovFeedback->kutatorKindNum, n, memory_order_release);
        for (uint32_t i = 0; i < n; i++) {
            ATOMIC_SET(globalCovFeedback->pidKutatorKind[i][my_thread_no].val,
                solfuzz_kutator_kind_count(i));
            if (solfuzz_kutator_kind_name &&
                !atomic_load_explicit(&globalCovFeedback->kutatorKindNameReady[i], memory_order_acquire)) {
                uint8_t expected = 0;
                if (atomic_compare_exchange_strong_explicit(
                        &globalCovFeedback->kutatorKindNameReady[i],
                        &expected, 1, memory_order_acq_rel, memory_order_acquire)) {
                    const char* name = solfuzz_kutator_kind_name(i);
                    snprintf(globalCovFeedback->kutatorKindNames[i],
                             _HF_KUTATOR_NAME_MAX, "%s", name ? name : "unknown");
                    atomic_store_explicit(&globalCovFeedback->kutatorKindNameReady[i], 2, memory_order_release);
                }
            }
        }
    }
    if (solfuzz_exec_fail_calls) {
        ATOMIC_SET(globalCovFeedback->pidExecFailCnt[my_thread_no].val,
            solfuzz_exec_fail_calls());
    }
    if (solfuzz_verify_calls) {
        ATOMIC_SET(globalCovFeedback->pidVerifyCnt[my_thread_no].val,
            solfuzz_verify_calls());
    }
    if (solfuzz_harness_reject_calls) {
        ATOMIC_SET(globalCovFeedback->pidHarnessRejectCnt[my_thread_no].val,
            solfuzz_harness_reject_calls());
    }
}

static void HonggfuzzPersistentLoop(void) {
    /*
     * HFUZZ_USE_CUSTOM_MUTATOR controls in-process structure-aware mutation:
     *   unset / "1" → enabled: call LLVMFuzzerCustomMutator each iteration
     *                 (protobuf parse → mutate → serialize per execution)
     *   "0"         → disabled: skip LLVMFuzzerCustomMutator entirely,
     *                 use honggfuzz byte-level external mutation only
     *
     * The env var is propagated by honggfuzz parent when --no-custom-mutator
     * is passed (see subproc.c).  It is also read by GetMutator() in
     * libfuzzer_macro.cc to select the internal Mutator implementation.
     *
     * WARNING: enabling this adds a full protobuf round-trip to every
     * execution, which can reduce throughput by 10-50x on complex messages.
     */
    bool use_custom_mutator = true;
    bool use_crossover      = true;
    unsigned int crossover_pct = 25;

    const char *replay_env = getenv("HFUZZ_REPLAY_MODE");
    if (replay_env && replay_env[0] == '1') {
        use_custom_mutator = false;
        use_crossover      = false;
        LOG_I("HFUZZ_REPLAY_MODE=1: all in-process mutations DISABLED");
    }

    const char *cm_env = getenv("HFUZZ_USE_CUSTOM_MUTATOR");
    if (cm_env && (cm_env[0] == '0' || cm_env[0] == 'n' || cm_env[0] == 'N')) {
        use_custom_mutator = false;
        use_crossover      = false;
        LOG_I("HFUZZ_USE_CUSTOM_MUTATOR=0: in-process custom mutation DISABLED (byte-level only)");
    }

    const char *xo_env = getenv("HFUZZ_USE_CROSSOVER");
    if (xo_env && (xo_env[0] == '0' || xo_env[0] == 'n' || xo_env[0] == 'N')) {
        use_crossover = false;
        LOG_I("HFUZZ_USE_CROSSOVER=0: in-process protobuf crossover DISABLED");
    }

    const char *xo_pct_env = getenv("HFUZZ_CROSSOVER_PCT");
    if (xo_pct_env) {
        unsigned long pct = strtoul(xo_pct_env, NULL, 10);
        if (pct <= 100) {
            crossover_pct = (unsigned int)pct;
            LOG_I("HFUZZ_CROSSOVER_PCT=%u: crossover fires %u%% of iterations",
                crossover_pct, crossover_pct);
        }
    }

    if (use_custom_mutator && LLVMFuzzerCustomMutator) {
        LOG_I("In-process protobuf mutation ENABLED (LLVMFuzzerCustomMutator linked)");
    } else if (!use_custom_mutator) {
        LOG_I("In-process protobuf mutation DISABLED by flag (honggfuzz byte-level mutation)");
    } else {
        LOG_W("LLVMFuzzerCustomMutator not linked -- using raw byte-level mutation only");
    }
    if (use_crossover && LLVMFuzzerCustomCrossOver) {
        LOG_I("In-process protobuf crossover ENABLED at %u%% (LLVMFuzzerCustomCrossOver linked)",
            crossover_pct);
    }

    for (;;) {
        size_t         len;
        const uint8_t* buf;

        performanceCheck();

        HonggfuzzFetchData(&buf, &len);
        ATOMIC_SET(globalCovFeedback->postMutInputLen[my_thread_no].val, 0);
        hf_mut_counter += 0x9e3779b9u;

        /*
         * Apply structure-aware in-process mutation via LLVMFuzzerCustomMutator
         * (provided by kutator / define_custom_mutator!(), or a hand-written
         * custom mutator).
         *
         * Without this, honggfuzz's byte-level external mutation produces
         * mostly unparseable protobuf data that the harness silently drops
         * (LLVMFuzzerTestOneInput returns 0 without ever calling the test).
         *
         * The custom mutator parses the corpus input as protobuf, does
         * structure-aware mutation, and serializes a valid message back.
         */
        if (use_custom_mutator && LLVMFuzzerCustomMutator && len > 0) {
            size_t copy_len = len;
            if (copy_len > _HF_INPUT_MAX_SIZE) {
                copy_len = _HF_INPUT_MAX_SIZE;
                ATOMIC_PRE_INC(globalCovFeedback->pidInputsTruncatedCnt[my_thread_no].val);
            }
            memcpy(hf_mut_buf, buf, copy_len);
            ATOMIC_PRE_INC(globalCovFeedback->pidCustomMutatorCallsCnt[my_thread_no].val);
            size_t mut_max = getInputMaxSize();
            if (mut_max == 0 || mut_max > _HF_INPUT_MAX_SIZE) mut_max = _HF_INPUT_MAX_SIZE;
            len = LLVMFuzzerCustomMutator(
                hf_mut_buf, copy_len, mut_max, hf_mut_counter);
            if (len > mut_max) len = mut_max;
            if (len > 0)
                ATOMIC_PRE_INC(globalCovFeedback->pidCustomMutatorSuccessesCnt[my_thread_no].val);
            buf = hf_mut_buf;

            /* Write mutated data back to the shared input region so the
               parent saves the actual crash-triggering input (post-mutation)
               rather than the pre-mutation corpus entry. */
            uint8_t* shared_input = getInputBuf();
            if (shared_input && len > 0) {
                size_t wb_len = len < mut_max ? len : mut_max;
                memcpy(shared_input, hf_mut_buf, wb_len);
                fetchSanPoison(shared_input, wb_len);
                ATOMIC_SET(globalCovFeedback->postMutInputLen[my_thread_no].val, wb_len);
            }
        }

        /* Schema-aware crossover with parent-provided donor (configurable rate) */
        if (use_crossover && LLVMFuzzerCustomCrossOver && len > 0
            && (hf_mut_counter % 100) < crossover_pct) {
            uint8_t* donor     = getDonorBuf();
            size_t   donor_len = getDonorLen();
            if (donor && donor_len > 0) {
                size_t xo_max = getInputMaxSize();
                if (xo_max == 0 || xo_max > _HF_INPUT_MAX_SIZE) xo_max = _HF_INPUT_MAX_SIZE;
                uint32_t xo_seed = hf_mut_counter ^ 0x12345678u;
                size_t new_len = LLVMFuzzerCustomCrossOver(
                    buf, len, donor, donor_len,
                    hf_xover_buf, xo_max, xo_seed);
                if (new_len > xo_max) new_len = xo_max;
                if (new_len > 0) {
                    len = new_len;
                    memcpy(hf_mut_buf, hf_xover_buf, len);
                    buf = hf_mut_buf;

                    uint8_t* shared_input_xo = getInputBuf();
                    if (shared_input_xo) {
                        size_t wb_len = len < xo_max ? len : xo_max;
                        memcpy(shared_input_xo, hf_mut_buf, wb_len);
                        fetchSanPoison(shared_input_xo, wb_len);
                        ATOMIC_SET(globalCovFeedback->postMutInputLen[my_thread_no].val, wb_len);
                    }
                }
            }
        }

        HonggfuzzRunOneInput(buf, len);
    }
}

static int HonggfuzzRunOneFile(const char* fname, uint8_t* buf) {
    int in_fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY));
    if (in_fd == -1) {
        PLOG_W("Cannot open '%s' as input, skipping", fname);
        return -1;
    }
    ssize_t len = files_readFromFd(in_fd, buf, _HF_INPUT_MAX_SIZE);
    close(in_fd);
    if (len < 0) {
        LOG_E("Couldn't read data from '%s': %s", fname, strerror(errno));
        return -1;
    }
    HonggfuzzRunOneInput(buf, len);
    return 0;
}

static int HonggfuzzRunFromDir(const char* dirpath, uint8_t* buf) {
    int dir_fd = TEMP_FAILURE_RETRY(open(dirpath, O_RDONLY | O_DIRECTORY));
    if (dir_fd == -1) {
        PLOG_E("Cannot open directory '%s'", dirpath);
        return -1;
    }
    DIR* dir = fdopendir(dir_fd);
    if (!dir) {
        PLOG_E("fdopendir('%s') failed", dirpath);
        close(dir_fd);
        return -1;
    }
    int ret = 0;
    size_t count = 0;
    for (;;) {
        errno = 0;
        struct dirent* ent = readdir(dir);
        if (!ent) {
            if (errno) {
                PLOG_E("readdir('%s') failed", dirpath);
                ret = -1;
            }
            break;
        }
        if (ent->d_name[0] == '.') continue;
        int file_fd = openat(dir_fd, ent->d_name, O_RDONLY);
        if (file_fd == -1) continue;
        struct stat st;
        if (fstat(file_fd, &st) == 0 && S_ISREG(st.st_mode)) {
            ssize_t len = files_readFromFd(file_fd, buf, _HF_INPUT_MAX_SIZE);
            if (len >= 0) {
                HonggfuzzRunOneInput(buf, len);
                count++;
            }
        }
        close(file_fd);
    }
    closedir(dir);
    LOG_I("Processed %zu files from directory '%s'", count, dirpath);
    return ret;
}

static int HonggfuzzRunFromFile(int argc, char** argv) {
    hf_replay_mode = true;
    LOG_I("🔥💃🔥💃🔥💃🔥💃🔥💃🔥💃🔥💃🔥💃🔥💃🔥💃🔥💃");
    LOG_I("Usage for fuzzing: honggfuzz -P [flags] -- %s", argv[0]);

    uint8_t* buf = (uint8_t*)util_Calloc(_HF_INPUT_MAX_SIZE);

    /* If no file arguments provided, read from stdin */
    if (argc <= 1) {
        LOG_I("Accepting input from '[STDIN]'");
        ssize_t len = files_readFromFd(STDIN_FILENO, buf, _HF_INPUT_MAX_SIZE);
        if (len < 0) {
            LOG_E("Couldn't read data from stdin: %s", strerror(errno));
            free(buf);
            return -1;
        }
        HonggfuzzRunOneInput(buf, len);
        free(buf);
        return 0;
    }

    /* Process each file argument */
    int ret = 0;
    for (int i = 1; i < argc; i++) {
        const char* fname = argv[i];
        struct stat st;
        if (stat(fname, &st) == -1) {
            PLOG_W("Cannot stat '%s', skipping", fname);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (HonggfuzzRunFromDir(fname, buf) != 0) ret = -1;
        } else if (S_ISREG(st.st_mode)) {
            if (HonggfuzzRunOneFile(fname, buf) != 0) ret = -1;
        }
    }

    free(buf);
    return ret;
}

/* Coverage replay entry point (defined in Rust when built with cargo hfuzz).
   Dispatched when SOLFUZZ_REPLAY_COVERAGE env var is set. */
__attribute__((weak)) int solfuzz_replay_coverage_main(int argc, char** argv);

int HonggfuzzMain(int argc, char** argv) {
    if (getenv("SOLFUZZ_REPLAY_COVERAGE") && solfuzz_replay_coverage_main) {
        return solfuzz_replay_coverage_main(argc, argv);
    }

    if (LLVMFuzzerInitialize) {
        LLVMFuzzerInitialize(&argc, &argv);
    }
    instrumentClearNewCov();

    if (!fetchIsInputAvailable()) {
        return HonggfuzzRunFromFile(argc, argv);
    }

    HonggfuzzPersistentLoop();
    return 0;
}

/*
 * Declare it 'weak', so it can be safely linked with regular binaries which
 * implement their own main()
 */
#if !defined(__CYGWIN__)
__attribute__((weak))
#endif /* !defined(__CYGWIN__) */
int main(int argc, char** argv) {
    return HonggfuzzMain(argc, argv);
}
