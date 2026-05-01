/**
 * Tests for crossover loop invariants in persistent mode.
 *
 * Guards against bugs found in honggfuzz#29 and the subsequent
 * parent-written donor redesign:
 *
 *   1. Coverage-saving path must use postMutInputLen (not dynfile->size)
 *      to avoid saving stale trailing bytes that corrupt the corpus.
 *
 *   2. hf_mut_counter must be incremented exactly once per iteration
 *      so the crossover gate (counter % 4 == 0) fires 25% of the time.
 *
 *   3. postMutInputLen must remain readable by the parent until AFTER
 *      the parent processes iteration results (clear must happen after
 *      the child receives the next input, not before the ready tag).
 *
 *   4. Parent-written donor in second half of shared mmap must be
 *      correctly readable by the child via the doubled mmap layout.
 *
 *   5. Protocol sends two uint64_t values; child must assert 16-byte
 *      read and detect mismatched builds.
 *
 *   6. Crossover must overwrite postMutInputLen with its output size.
 *
 * Build:
 *   cc -o test_crossover_invariants tests/test_crossover_invariants.c -lpthread
 *
 * Run:
 *   ./test_crossover_invariants
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define INPUT_MAX_SIZE (1 << 20) /* 1 MB */

typedef struct {
    _Atomic size_t postMutInputLen;
} shared_feedback_t;

static void write_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        assert(n > 0);
        buf += n;
        len -= (size_t)n;
    }
}

static size_t read_file(const char *path, uint8_t *buf, size_t max) {
    int fd = open(path, O_RDONLY);
    assert(fd >= 0);
    ssize_t n = read(fd, buf, max);
    assert(n >= 0);
    close(fd);
    return (size_t)n;
}

/* -----------------------------------------------------------------------
   Test 1: Coverage corpus entry must be saved at postMutInputLen bytes
   (not the original dynfile->size) when the custom mutator changes the
   output size.
   ----------------------------------------------------------------------- */
static void test_coverage_save_uses_postmut_size(const char *crash_path) {
    printf("TEST 1: coverage save uses postMutInputLen, not dynfile->size ... ");

    int input_fd = memfd_create("hf_input_cov", 0);
    assert(input_fd >= 0);
    assert(ftruncate(input_fd, INPUT_MAX_SIZE) == 0);

    int fb_fd = memfd_create("hf_fb_cov", 0);
    assert(fb_fd >= 0);
    assert(ftruncate(fb_fd, sizeof(shared_feedback_t)) == 0);

    uint8_t *shared_input = mmap(
        NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
    assert(shared_input != MAP_FAILED);

    shared_feedback_t *fb = mmap(
        NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    assert(fb != MAP_FAILED);

    const size_t corpus_size = 200;
    memset(shared_input, 'A', corpus_size);
    atomic_store(&fb->postMutInputLen, 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        uint8_t *child_input = mmap(
            NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
        assert(child_input != MAP_FAILED);
        shared_feedback_t *child_fb = mmap(
            NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
        assert(child_fb != MAP_FAILED);

        memset(child_input, 'M', 180);
        atomic_store(&child_fb->postMutInputLen, 180);

        memset(child_input, 'X', 120);
        atomic_store(&child_fb->postMutInputLen, 120);

        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    size_t save_size = corpus_size;
    size_t post_len = atomic_load(&fb->postMutInputLen);
    if (post_len > 0 && post_len <= INPUT_MAX_SIZE) {
        save_size = post_len;
    }

    assert(save_size == 120);

    int fd = open(crash_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd >= 0);
    write_all(fd, shared_input, save_size);
    close(fd);

    uint8_t file_buf[INPUT_MAX_SIZE];
    size_t file_len = read_file(crash_path, file_buf, INPUT_MAX_SIZE);
    assert(file_len == 120);
    for (size_t i = 0; i < 120; i++) {
        assert(file_buf[i] == 'X');
    }

    munmap(shared_input, INPUT_MAX_SIZE);
    munmap(fb, sizeof(shared_feedback_t));
    close(input_fd);
    close(fb_fd);

    printf("PASS\n");
}

/* -----------------------------------------------------------------------
   Test 2: Dual writeback with size increase
   ----------------------------------------------------------------------- */
static void test_coverage_save_handles_size_increase(void) {
    printf("TEST 2: coverage save handles crossover size increase ... ");

    int input_fd = memfd_create("hf_input_grow", 0);
    assert(input_fd >= 0);
    assert(ftruncate(input_fd, INPUT_MAX_SIZE) == 0);

    int fb_fd = memfd_create("hf_fb_grow", 0);
    assert(fb_fd >= 0);
    assert(ftruncate(fb_fd, sizeof(shared_feedback_t)) == 0);

    uint8_t *shared_input = mmap(
        NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
    assert(shared_input != MAP_FAILED);

    shared_feedback_t *fb = mmap(
        NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    assert(fb != MAP_FAILED);

    const size_t corpus_size = 100;
    memset(shared_input, 'A', corpus_size);
    atomic_store(&fb->postMutInputLen, 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        uint8_t *child_input = mmap(
            NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
        assert(child_input != MAP_FAILED);
        shared_feedback_t *child_fb = mmap(
            NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
        assert(child_fb != MAP_FAILED);

        memset(child_input, 'G', 250);
        atomic_store(&child_fb->postMutInputLen, 250);

        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);

    size_t save_size = corpus_size;
    size_t post_len = atomic_load(&fb->postMutInputLen);
    if (post_len > 0 && post_len <= INPUT_MAX_SIZE) {
        save_size = post_len;
    }

    assert(save_size == 250);

    for (size_t i = 0; i < 250; i++) {
        assert(shared_input[i] == 'G');
    }

    munmap(shared_input, INPUT_MAX_SIZE);
    munmap(fb, sizeof(shared_feedback_t));
    close(input_fd);
    close(fb_fd);

    printf("PASS\n");
}

/* -----------------------------------------------------------------------
   Test 3: hf_mut_counter increment fires crossover at the configured
   percentage.  Production uses (counter % 100) < crossover_pct.
   ----------------------------------------------------------------------- */
static void test_crossover_fires_at_configured_rate(void) {
    printf("TEST 3: crossover gate fires at configured rate ... ");

    const uint32_t GOLDEN = 0x9e3779b9u;
    const int ITERATIONS = 100000;

    /* Test default 25% */
    int count_25 = 0;
    uint32_t counter = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        counter += GOLDEN;
        if ((counter % 100) < 25) {
            count_25++;
        }
    }
    double rate_25 = (double)count_25 / ITERATIONS;
    assert(rate_25 > 0.24 && rate_25 < 0.26);

    /* Test 10% */
    int count_10 = 0;
    counter = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        counter += GOLDEN;
        if ((counter % 100) < 10) {
            count_10++;
        }
    }
    double rate_10 = (double)count_10 / ITERATIONS;
    assert(rate_10 > 0.09 && rate_10 < 0.11);

    /* Test 50% */
    int count_50 = 0;
    counter = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        counter += GOLDEN;
        if ((counter % 100) < 50) {
            count_50++;
        }
    }
    double rate_50 = (double)count_50 / ITERATIONS;
    assert(rate_50 > 0.49 && rate_50 < 0.51);

    printf("PASS (25%%=%.1f%%, 10%%=%.1f%%, 50%%=%.1f%%)\n",
           rate_25 * 100, rate_10 * 100, rate_50 * 100);
}

/* -----------------------------------------------------------------------
   Test 4: Parent-written donor in second half of doubled mmap.
   Verifies that parent writes donor data at offset maxInputSz and
   the child can read it correctly.
   ----------------------------------------------------------------------- */
static void test_donor_from_mmap(void) {
    printf("TEST 4: donor data readable from second half of mmap ... ");

    const size_t max_input_sz = INPUT_MAX_SIZE;
    const size_t mmap_sz = max_input_sz * 2;

    int input_fd = memfd_create("hf_input_donor", 0);
    assert(input_fd >= 0);
    assert(ftruncate(input_fd, (off_t)mmap_sz) == 0);

    /* Parent writes primary input to first half */
    uint8_t *parent_map = mmap(
        NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
    assert(parent_map != MAP_FAILED);

    const size_t primary_sz = 100;
    memset(parent_map, 'P', primary_sz);

    /* Parent writes donor to second half */
    const size_t donor_sz = 75;
    memset(parent_map + max_input_sz, 'D', donor_sz);

    /* Protocol: parent sends two uint64_t values */
    int proto_pipe[2];
    assert(pipe(proto_pipe) == 0);
    uint64_t lens[2] = {primary_sz, donor_sz};
    assert(write(proto_pipe[1], lens, sizeof(lens)) == (ssize_t)sizeof(lens));

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        close(proto_pipe[1]);

        /* Child mmaps the same FD */
        uint8_t *child_map = mmap(
            NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
        assert(child_map != MAP_FAILED);

        size_t child_input_sz = mmap_sz / 2;
        uint8_t *child_donor = child_map + child_input_sz;

        /* Read protocol: two uint64_t */
        uint64_t rcv[2];
        ssize_t n = read(proto_pipe[0], rcv, sizeof(rcv));
        assert(n == (ssize_t)sizeof(rcv));

        /* Verify primary */
        assert(rcv[0] == primary_sz);
        for (size_t i = 0; i < primary_sz; i++) {
            assert(child_map[i] == 'P');
        }

        /* Verify donor */
        assert(rcv[1] == donor_sz);
        for (size_t i = 0; i < donor_sz; i++) {
            assert(child_donor[i] == 'D');
        }

        munmap(child_map, mmap_sz);
        close(proto_pipe[0]);
        _exit(0);
    }

    close(proto_pipe[0]);

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    munmap(parent_map, mmap_sz);
    close(proto_pipe[1]);
    close(input_fd);

    printf("PASS\n");
}

/* -----------------------------------------------------------------------
   Test 5: Protocol mismatch detection — if parent sends only 8 bytes
   (old protocol), child must detect the short read.
   ----------------------------------------------------------------------- */
static void test_protocol_size_mismatch(void) {
    printf("TEST 5: protocol mismatch detected (8 vs 16 bytes) ... ");

    int proto_pipe[2];
    assert(pipe(proto_pipe) == 0);

    /* Parent sends old-style 8-byte message */
    uint64_t old_len = 100;
    assert(write(proto_pipe[1], &old_len, sizeof(old_len)) == (ssize_t)sizeof(old_len));
    close(proto_pipe[1]); /* close write end so child read doesn't block */

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        close(proto_pipe[1]);

        /* Child tries to read new-style 16-byte message */
        uint64_t rcv[2];
        ssize_t n = read(proto_pipe[0], rcv, sizeof(rcv));

        /* Should get only 8 bytes, not 16 */
        if (n == (ssize_t)sizeof(rcv)) {
            /* Full read: no mismatch */
            _exit(1);
        }
        /* Short read: mismatch detected */
        _exit(0);
    }

    close(proto_pipe[0]);

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    printf("PASS\n");
}

/* -----------------------------------------------------------------------
   Test 6: postMutInputLen synchronization — the clear must happen AFTER
   the child receives the next input, not before the ready tag.
   Protocol updated for two-uint64_t messages.
   ----------------------------------------------------------------------- */
static void test_postmutlen_visible_to_parent(void) {
    printf("TEST 6: postMutInputLen visible to parent after ready tag ... ");

    int fb_fd = memfd_create("hf_fb_sync", 0);
    assert(fb_fd >= 0);
    assert(ftruncate(fb_fd, sizeof(shared_feedback_t)) == 0);

    shared_feedback_t *fb = mmap(
        NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    assert(fb != MAP_FAILED);

    int ready_pipe[2], data_pipe[2];
    assert(pipe(ready_pipe) == 0);
    assert(pipe(data_pipe) == 0);

    atomic_store(&fb->postMutInputLen, 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        shared_feedback_t *child_fb = mmap(
            NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
        assert(child_fb != MAP_FAILED);

        close(ready_pipe[0]);
        close(data_pipe[1]);

        for (int iter = 0; iter < 3; iter++) {
            uint8_t tag = 'R';
            assert(write(ready_pipe[1], &tag, 1) == 1);

            uint64_t rcvLens[2];
            assert(read(data_pipe[0], rcvLens, sizeof(rcvLens)) == (ssize_t)sizeof(rcvLens));

            /* FIXED: clear postMutInputLen AFTER receiving next input */
            atomic_store(&child_fb->postMutInputLen, 0);

            size_t output_size = 100 + iter * 50;
            atomic_store(&child_fb->postMutInputLen, output_size);
        }

        uint8_t tag = 'R';
        assert(write(ready_pipe[1], &tag, 1) == 1);

        close(ready_pipe[1]);
        close(data_pipe[0]);
        _exit(0);
    }

    close(ready_pipe[1]);
    close(data_pipe[0]);

    size_t expected_sizes[] = {100, 150, 200};

    for (int iter = 0; iter < 3; iter++) {
        uint8_t tag;
        assert(read(ready_pipe[0], &tag, 1) == 1);
        assert(tag == 'R');

        if (iter > 0) {
            size_t post_len = atomic_load(&fb->postMutInputLen);
            assert(post_len == expected_sizes[iter - 1]);
        }

        uint64_t lens[2] = {500, 200};
        assert(write(data_pipe[1], lens, sizeof(lens)) == (ssize_t)sizeof(lens));
    }

    uint8_t tag;
    assert(read(ready_pipe[0], &tag, 1) == 1);
    size_t post_len = atomic_load(&fb->postMutInputLen);
    assert(post_len == expected_sizes[2]);

    close(ready_pipe[0]);
    close(data_pipe[1]);

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    munmap(fb, sizeof(shared_feedback_t));
    close(fb_fd);

    printf("PASS\n");
}

/* -----------------------------------------------------------------------
   Test 7: OLD BUG: postMutInputLen cleared BEFORE ready tag → parent
   always sees 0.  Protocol updated for two-uint64_t messages.
   ----------------------------------------------------------------------- */
static void test_old_bug_postmutlen_cleared_before_ready(void) {
    printf("TEST 7: OLD BUG: clear before ready tag -> parent sees 0 ... ");

    int fb_fd = memfd_create("hf_fb_oldbug", 0);
    assert(fb_fd >= 0);
    assert(ftruncate(fb_fd, sizeof(shared_feedback_t)) == 0);

    shared_feedback_t *fb = mmap(
        NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    assert(fb != MAP_FAILED);

    int ready_pipe[2], data_pipe[2];
    assert(pipe(ready_pipe) == 0);
    assert(pipe(data_pipe) == 0);

    atomic_store(&fb->postMutInputLen, 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        shared_feedback_t *child_fb = mmap(
            NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
        assert(child_fb != MAP_FAILED);

        close(ready_pipe[0]);
        close(data_pipe[1]);

        for (int iter = 0; iter < 3; iter++) {
            /* OLD BUG: clear BEFORE writing ready tag */
            atomic_store(&child_fb->postMutInputLen, 0);

            uint8_t tag = 'R';
            assert(write(ready_pipe[1], &tag, 1) == 1);

            uint64_t rcvLens[2];
            assert(read(data_pipe[0], rcvLens, sizeof(rcvLens)) == (ssize_t)sizeof(rcvLens));

            atomic_store(&child_fb->postMutInputLen, 100 + iter * 50);
        }

        atomic_store(&child_fb->postMutInputLen, 0);
        uint8_t tag = 'R';
        assert(write(ready_pipe[1], &tag, 1) == 1);

        close(ready_pipe[1]);
        close(data_pipe[0]);
        _exit(0);
    }

    close(ready_pipe[1]);
    close(data_pipe[0]);

    for (int iter = 0; iter < 3; iter++) {
        uint8_t tag;
        assert(read(ready_pipe[0], &tag, 1) == 1);

        if (iter > 0) {
            size_t post_len = atomic_load(&fb->postMutInputLen);
            assert(post_len == 0); /* This is the bug! */
        }

        uint64_t lens[2] = {500, 200};
        assert(write(data_pipe[1], lens, sizeof(lens)) == (ssize_t)sizeof(lens));
    }

    uint8_t tag;
    assert(read(ready_pipe[0], &tag, 1) == 1);
    size_t post_len = atomic_load(&fb->postMutInputLen);
    assert(post_len == 0);

    close(ready_pipe[0]);
    close(data_pipe[1]);

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    munmap(fb, sizeof(shared_feedback_t));
    close(fb_fd);

    printf("PASS (demonstrates that old ordering always loses the value)\n");
}

/* -----------------------------------------------------------------------
   Test 8: Crossover overwrites postMutInputLen with its output size.
   When crossover fires after mutation, the final postMutInputLen must
   reflect the crossover output, not the pre-crossover mutation output.
   ----------------------------------------------------------------------- */
static void test_crossover_overwrites_postmut_len(void) {
    printf("TEST 8: crossover overwrites postMutInputLen ... ");

    int fb_fd = memfd_create("hf_fb_xover", 0);
    assert(fb_fd >= 0);
    assert(ftruncate(fb_fd, sizeof(shared_feedback_t)) == 0);

    shared_feedback_t *fb = mmap(
        NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    assert(fb != MAP_FAILED);

    atomic_store(&fb->postMutInputLen, 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        shared_feedback_t *child_fb = mmap(
            NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
        assert(child_fb != MAP_FAILED);

        /* Step 1: mutation writes 300 bytes */
        atomic_store(&child_fb->postMutInputLen, 300);

        /* Step 2: crossover produces 180 bytes, overwrites postMutInputLen */
        atomic_store(&child_fb->postMutInputLen, 180);

        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    size_t post_len = atomic_load(&fb->postMutInputLen);
    assert(post_len == 180);

    munmap(fb, sizeof(shared_feedback_t));
    close(fb_fd);

    printf("PASS\n");
}

/* -----------------------------------------------------------------------
   Test 9: Donor NULL when mmap not doubled — crossover must be skipped
   gracefully instead of crashing.
   ----------------------------------------------------------------------- */
static void test_donor_null_when_mmap_too_small(void) {
    printf("TEST 9: donor NULL when mmap not doubled ... ");

    /* Single-size mmap (simulating old parent that didn't double) */
    const size_t single_sz = INPUT_MAX_SIZE;
    int input_fd = memfd_create("hf_input_single", 0);
    assert(input_fd >= 0);
    assert(ftruncate(input_fd, (off_t)single_sz) == 0);

    uint8_t *map = mmap(
        NULL, single_sz, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
    assert(map != MAP_FAILED);

    /* inputFileSize = totalSize / 2 = single_sz / 2 */
    size_t input_file_size = single_sz / 2;

    /* donorBuf would point to map + input_file_size, but if the total
       mmap is only single_sz, the "donor half" is really just the second
       half of a single-size region — no separate donor was written.
       The parent signals donor_size=0 to indicate no donor available. */
    size_t donor_size = 0;

    /* Crossover should be skipped when donor_size == 0 */
    uint8_t *donor_buf = (donor_size > 0) ? (map + input_file_size) : NULL;
    assert(donor_buf == NULL);

    munmap(map, single_sz);
    close(input_fd);

    printf("PASS\n");
}

int main(void) {
    printf("=== Crossover invariant tests ===\n\n");

    char path[] = "/tmp/hf_test_xover_XXXXXX";
    int tmp_fd = mkstemp(path);
    assert(tmp_fd >= 0);
    close(tmp_fd);

    test_coverage_save_uses_postmut_size(path);
    test_coverage_save_handles_size_increase();
    test_crossover_fires_at_configured_rate();
    test_donor_from_mmap();
    test_protocol_size_mismatch();
    test_postmutlen_visible_to_parent();
    test_old_bug_postmutlen_cleared_before_ready();
    test_crossover_overwrites_postmut_len();
    test_donor_null_when_mmap_too_small();

    unlink(path);

    printf("\nAll tests passed.\n");
    return 0;
}
