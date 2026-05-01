#include "libhfuzz/fetch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"

/*
 * If this signature is visible inside a binary, it's probably a persistent-style fuzzing program.
 * This discovery mode is employed by honggfuzz
 */
__attribute__((visibility("default"))) __attribute__((used)) const char* LIBHFUZZ_module_fetch =
    _HF_PERSISTENT_SIG;

static uint8_t* inputFile     = NULL;
static size_t   inputFileSize = 0;
static uint8_t* donorBuf      = NULL;
static size_t   donorLen      = 0;

__attribute__((constructor)) static void init(void) {
    if (fcntl(_HF_INPUT_FD, F_GETFD) == -1 && errno == EBADF) {
        return;
    }

    struct stat st;
    if (fstat(_HF_INPUT_FD, &st) == -1) {
        PLOG_F("fstat(fd=%d) of the input file failed", _HF_INPUT_FD);
    }

    size_t totalSize = (size_t)st.st_size;
    size_t map_size  = totalSize > 0 ? totalSize : _HF_INPUT_MAX_SIZE;
    if ((inputFile = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, _HF_INPUT_FD, 0)) ==
        MAP_FAILED) {
        PLOG_F("mmap(fd=%d, size=%zu) of the input file failed", _HF_INPUT_FD, map_size);
    }

    /* When persistent+custom-mutator is active, parent sets HFUZZ_MAX_INPUT_SZ
       and allocates 2 * maxInputSz: first half = primary, second half = donor. */
    const char* maxSzEnv = getenv("HFUZZ_MAX_INPUT_SZ");
    if (maxSzEnv) {
        inputFileSize = (size_t)strtoull(maxSzEnv, NULL, 10);
        if (inputFileSize > _HF_INPUT_MAX_SIZE) inputFileSize = _HF_INPUT_MAX_SIZE;
        if (inputFileSize > 0 && totalSize >= inputFileSize * 2) {
            donorBuf = inputFile + inputFileSize;
        }
    } else {
        inputFileSize = totalSize;
        if (inputFileSize > _HF_INPUT_MAX_SIZE) inputFileSize = _HF_INPUT_MAX_SIZE;
    }
}

uint8_t* getInputBuf(void) {
    return inputFile;
}

size_t getInputMaxSize(void) {
    return inputFileSize;
}

/*
 * Instruct *SAN to treat the input buffer to be of a specific size, treating all accesses
 * beyond that as access violations
 */
void fetchSanPoison(const uint8_t* buf, size_t len) {
/* MacOS X linker doesn't like those */
#if defined(_HF_ARCH_DARWIN) || defined(__APPLE__)
    return;
#endif /* defined(_HF_ARCH_DARWIN) */

    size_t mapped = inputFileSize > 0 ? inputFileSize : _HF_INPUT_MAX_SIZE;
    if (len > mapped) len = mapped;

    __attribute__((weak)) extern void __asan_unpoison_memory_region(const void* addr, size_t sz);
    __attribute__((weak)) extern void __msan_unpoison(const void* addr, size_t sz);

    /* Unpoison the whole mapped area first */
    if (__asan_unpoison_memory_region) {
        __asan_unpoison_memory_region(buf, mapped);
    }
    if (__msan_unpoison) {
        __msan_unpoison(buf, mapped);
    }

    __attribute__((weak)) extern void __asan_poison_memory_region(const void* addr, size_t sz);
    __attribute__((weak)) extern void __msan_poison(const void* addr, size_t sz);
    /* Poison the remainder of the buffer (beyond len) */
    if (__asan_poison_memory_region) {
        __asan_poison_memory_region(&buf[len], mapped - len);
    }
    if (__msan_poison) {
        __msan_poison(&buf[len], mapped - len);
    }
}

void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr) {
    if (!files_writeToFd(_HF_PERSISTENT_FD, &HFReadyTag, sizeof(HFReadyTag))) {
        LOG_F("writeToFd(size=%zu, readyTag) failed", sizeof(HFReadyTag));
    }

    uint64_t rcvLens[2];
    ssize_t  sz = files_readFromFd(_HF_PERSISTENT_FD, (uint8_t*)rcvLens, sizeof(rcvLens));
    if (sz == -1) {
        PLOG_F("readFromFd(fd=%d, size=%zu) failed", _HF_PERSISTENT_FD, sizeof(rcvLens));
    }
    if (sz != (ssize_t)sizeof(rcvLens)) {
        LOG_F("Protocol mismatch: expected %zu bytes, received %zd. "
              "Rebuild both honggfuzz and the fuzz harness.",
            sizeof(rcvLens), sz);
    }

    *buf_ptr = inputFile;
    size_t mapped = inputFileSize > 0 ? inputFileSize : _HF_INPUT_MAX_SIZE;
    *len_ptr = (size_t)rcvLens[0] > mapped ? mapped : (size_t)rcvLens[0];
    donorLen = (size_t)rcvLens[1] > mapped ? mapped : (size_t)rcvLens[1];

    fetchSanPoison(inputFile, *len_ptr);
    if (donorBuf && donorLen > 0) {
        fetchSanPoison(donorBuf, donorLen);
    }

    if (lseek(_HF_INPUT_FD, (off_t)0, SEEK_SET) == -1) {
        PLOG_W("lseek(_HF_INPUT_FD=%d, 0)", _HF_INPUT_FD);
    }
}

uint8_t* getDonorBuf(void) {
    return donorBuf;
}

size_t getDonorLen(void) {
    return donorLen;
}

bool fetchIsInputAvailable(void) {
    LOG_D("Current module: %s", LIBHFUZZ_module_fetch);
    return (inputFile != NULL);
}
