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

__attribute__((weak)) int LLVMFuzzerInitialize(
    int* argc HF_ATTR_UNUSED, char*** argv HF_ATTR_UNUSED) {
    return 1;
}

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
 * libprotobuf-mutator's Mutator calls this for scalar field mutations
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

static uint8_t  hf_mut_buf[_HF_INPUT_MAX_SIZE];
static uint32_t hf_mut_counter = 0;

/* Shared coverage feedback struct (mmap'd, visible to parent for metrics).
   my_thread_no indexes our per-thread slot.  Both from instrument.c. */
extern feedback_t* globalCovFeedback;
extern uint32_t    my_thread_no;

void HF_ITER(const uint8_t** buf_ptr, size_t* len_ptr) {
    HonggfuzzFetchData(buf_ptr, len_ptr);
}

/* Proto parse counter accessors (defined in libprotobuf-mutator libfuzzer_macro.cc,
   linked into the same process).  We accumulate deltas into shared memory so the
   honggfuzz parent can read the aggregate across all child processes. */
__attribute__((weak)) uint64_t solfuzz_proto_test_one_input_calls(void);
__attribute__((weak)) uint64_t solfuzz_proto_test_one_input_runs(void);
__attribute__((weak)) uint64_t solfuzz_lpm_mutate_calls(void);
__attribute__((weak)) uint64_t solfuzz_lpm_crossover_calls(void);
__attribute__((weak)) uint64_t solfuzz_lpm_parse_fail_calls(void);
__attribute__((weak)) uint64_t solfuzz_postprocessor_calls(void);
__attribute__((weak)) uint64_t solfuzz_elf_fixup_ok_calls(void);
__attribute__((weak)) uint64_t solfuzz_exec_fail_calls(void);
__attribute__((weak)) uint64_t solfuzz_verify_calls(void);

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

    if (solfuzz_proto_test_one_input_calls) {
        ATOMIC_SET(globalCovFeedback->pidProtoParseCallsCnt[my_thread_no].val,
            solfuzz_proto_test_one_input_calls());
    }
    if (solfuzz_proto_test_one_input_runs) {
        ATOMIC_SET(globalCovFeedback->pidProtoParseSuccessesCnt[my_thread_no].val,
            solfuzz_proto_test_one_input_runs());
    }
    if (solfuzz_lpm_mutate_calls) {
        ATOMIC_SET(globalCovFeedback->pidLpmMutateCnt[my_thread_no].val,
            solfuzz_lpm_mutate_calls());
    }
    if (solfuzz_lpm_crossover_calls) {
        ATOMIC_SET(globalCovFeedback->pidLpmCrossOverCnt[my_thread_no].val,
            solfuzz_lpm_crossover_calls());
    }
    if (solfuzz_lpm_parse_fail_calls) {
        ATOMIC_SET(globalCovFeedback->pidLpmParseFailCnt[my_thread_no].val,
            solfuzz_lpm_parse_fail_calls());
    }
    if (solfuzz_postprocessor_calls) {
        ATOMIC_SET(globalCovFeedback->pidPostProcessorCnt[my_thread_no].val,
            solfuzz_postprocessor_calls());
    }
    if (solfuzz_elf_fixup_ok_calls) {
        ATOMIC_SET(globalCovFeedback->pidElfFixupOkCnt[my_thread_no].val,
            solfuzz_elf_fixup_ok_calls());
    }
    if (solfuzz_exec_fail_calls) {
        ATOMIC_SET(globalCovFeedback->pidExecFailCnt[my_thread_no].val,
            solfuzz_exec_fail_calls());
    }
    if (solfuzz_verify_calls) {
        ATOMIC_SET(globalCovFeedback->pidVerifyCnt[my_thread_no].val,
            solfuzz_verify_calls());
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

    const char *cm_env = getenv("HFUZZ_USE_CUSTOM_MUTATOR");
    if (cm_env && (cm_env[0] == '0' || cm_env[0] == 'n' || cm_env[0] == 'N')) {
        use_custom_mutator = false;
        LOG_I("HFUZZ_USE_CUSTOM_MUTATOR=0: in-process custom mutation DISABLED (byte-level only)");
    }

    if (use_custom_mutator && LLVMFuzzerCustomMutator) {
        LOG_I("In-process protobuf mutation ENABLED (LLVMFuzzerCustomMutator linked)");
    } else if (!use_custom_mutator) {
        LOG_I("In-process protobuf mutation DISABLED by flag (honggfuzz byte-level mutation)");
    } else {
        LOG_W("LLVMFuzzerCustomMutator not linked -- using raw byte-level mutation only");
    }

    for (;;) {
        size_t         len;
        const uint8_t* buf;

        performanceCheck();

        HonggfuzzFetchData(&buf, &len);

        /*
         * Apply structure-aware in-process mutation via LLVMFuzzerCustomMutator
         * (provided by libprotobuf-mutator / DEFINE_BINARY_PROTO_FUZZER, or a
         * hand-written custom mutator).
         *
         * Without this, honggfuzz's byte-level external mutation produces
         * mostly unparseable protobuf data that LoadProtoInput silently drops
         * (LLVMFuzzerTestOneInput returns 0 without ever calling the test).
         *
         * The custom mutator parses whatever honggfuzz gives us (protobuf is
         * lenient), does structure-aware mutation, and serializes a valid
         * message back.  libprotobuf-mutator also caches the parsed result so
         * the subsequent LoadProtoInput in TestOneInput is a free cache hit.
         */
        if (use_custom_mutator && LLVMFuzzerCustomMutator && len > 0) {
            size_t copy_len = len;
            if (copy_len > _HF_INPUT_MAX_SIZE) {
                copy_len = _HF_INPUT_MAX_SIZE;
                ATOMIC_PRE_INC(globalCovFeedback->pidInputsTruncatedCnt[my_thread_no].val);
            }
            memcpy(hf_mut_buf, buf, copy_len);
            hf_mut_counter += 0x9e3779b9u;
            ATOMIC_PRE_INC(globalCovFeedback->pidCustomMutatorCallsCnt[my_thread_no].val);
            len = LLVMFuzzerCustomMutator(
                hf_mut_buf, copy_len, _HF_INPUT_MAX_SIZE, hf_mut_counter);
            if (len > 0)
                ATOMIC_PRE_INC(globalCovFeedback->pidCustomMutatorSuccessesCnt[my_thread_no].val);
            buf = hf_mut_buf;
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

int HonggfuzzMain(int argc, char** argv) {
    LLVMFuzzerInitialize(&argc, &argv);
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
