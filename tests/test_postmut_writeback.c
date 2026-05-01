/**
 * Test: crash file persistence saves post-mutation data.
 *
 * This test simulates the full flow for three scenarios:
 *   1. Custom mutation: mutator transforms input, writeback persists it
 *   2. Custom crossover: crossover produces new input, writeback persists it
 *   3. No writeback (old behavior): crash file contains wrong data
 *
 * Build:
 *   cc -o test_postmut_writeback tests/test_postmut_writeback.c
 *
 * Run:
 *   ./test_postmut_writeback
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

#define INPUT_MAX_SIZE (1 << 20) /* 1 MB (smaller than production _HF_INPUT_MAX_SIZE for test speed) */

/* Minimal reproduction of the shared feedback field.
   In production this is sizeCacheLine_t inside feedback_t. */
typedef struct {
    _Atomic size_t postMutInputLen;
} shared_feedback_t;

/* Simulate the parent's crash-saving logic from trace.c / subproc.c.
   This is the code path that reads postMutInputLen to determine how
   many bytes to write to the crash file. */
static void write_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        assert(n > 0);
        buf += n;
        len -= (size_t)n;
    }
}

static void save_crash_file(const char *path, const uint8_t *shared_input,
    size_t dynfile_size, const shared_feedback_t *fb, size_t max_input_sz) {
    size_t crash_size = dynfile_size;
    size_t post_len = atomic_load(&fb->postMutInputLen);
    if (post_len > 0 && post_len <= max_input_sz) {
        crash_size = post_len;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd >= 0);
    write_all(fd, shared_input, crash_size);
    close(fd);
}

/* Read a file into a buffer. Returns the number of bytes read. */
static size_t read_file(const char *path, uint8_t *buf, size_t max) {
    int fd = open(path, O_RDONLY);
    assert(fd >= 0);
    ssize_t n = read(fd, buf, max);
    assert(n >= 0);
    close(fd);
    return (size_t)n;
}

/* -----------------------------------------------------------------------
   Test 1: Custom mutation writeback → crash file has post-mutation data
   ----------------------------------------------------------------------- */
static void test_mutation_crash_file_has_postmut_data(const char *crash_path) {
    printf("TEST: mutation crash file contains post-mutation data ... ");

    int input_fd = memfd_create("hf_input_mut", 0);
    assert(input_fd >= 0);
    assert(ftruncate(input_fd, INPUT_MAX_SIZE) == 0);

    int fb_fd = memfd_create("hf_fb_mut", 0);
    assert(fb_fd >= 0);
    assert(ftruncate(fb_fd, sizeof(shared_feedback_t)) == 0);

    uint8_t *parent_input = mmap(
        NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
    assert(parent_input != MAP_FAILED);

    shared_feedback_t *parent_fb = mmap(
        NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    assert(parent_fb != MAP_FAILED);

    /* Parent writes pre-mutation corpus data to shared input */
    const char *pre_mut = "PRE_MUTATION_CORPUS_DATA_THAT_DOES_NOT_CRASH";
    size_t pre_len = strlen(pre_mut);
    memcpy(parent_input, pre_mut, pre_len);
    atomic_store(&parent_fb->postMutInputLen, 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        /* Child: simulate LLVMFuzzerCustomMutator + writeback */
        uint8_t *child_input = mmap(
            NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
        assert(child_input != MAP_FAILED);

        shared_feedback_t *child_fb = mmap(
            NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
        assert(child_fb != MAP_FAILED);

        /* Custom mutator: input → hf_mut_buf → transform */
        uint8_t mut_buf[INPUT_MAX_SIZE];
        memcpy(mut_buf, child_input, pre_len);
        const char *post_mut = "POST_MUTATION_PROTOBUF_THAT_TRIGGERS_CRASH";
        size_t post_len = strlen(post_mut);
        memcpy(mut_buf, post_mut, post_len);

        /* Writeback (the fix in persistent.c) */
        memcpy(child_input, mut_buf, post_len);
        atomic_store(&child_fb->postMutInputLen, post_len);

        _exit(134); /* SIGABRT */
    }

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 134);

    /* Parent saves crash file using the same logic as trace.c */
    save_crash_file(crash_path, parent_input, pre_len, parent_fb, INPUT_MAX_SIZE);

    /* Verify the crash file contains POST-mutation data */
    uint8_t file_buf[INPUT_MAX_SIZE];
    size_t file_len = read_file(crash_path, file_buf, INPUT_MAX_SIZE);

    const char *expected = "POST_MUTATION_PROTOBUF_THAT_TRIGGERS_CRASH";
    size_t expected_len = strlen(expected);
    assert(file_len == expected_len);
    assert(memcmp(file_buf, expected, expected_len) == 0);
    assert(memcmp(file_buf, "PRE_MUTATION", 12) != 0);

    munmap(parent_input, INPUT_MAX_SIZE);
    munmap(parent_fb, sizeof(shared_feedback_t));
    close(input_fd);
    close(fb_fd);

    printf("PASS\n");
}

/* -----------------------------------------------------------------------
   Test 2: Custom crossover writeback → crash file has crossover data
   ----------------------------------------------------------------------- */
static void test_crossover_crash_file_has_postmut_data(const char *crash_path) {
    printf("TEST: crossover crash file contains post-crossover data ... ");

    int input_fd = memfd_create("hf_input_xo", 0);
    assert(input_fd >= 0);
    assert(ftruncate(input_fd, INPUT_MAX_SIZE) == 0);

    int fb_fd = memfd_create("hf_fb_xo", 0);
    assert(fb_fd >= 0);
    assert(ftruncate(fb_fd, sizeof(shared_feedback_t)) == 0);

    uint8_t *parent_input = mmap(
        NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
    assert(parent_input != MAP_FAILED);

    shared_feedback_t *parent_fb = mmap(
        NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    assert(parent_fb != MAP_FAILED);

    /* Parent writes pre-mutation corpus data */
    const char *pre_mut = "PRE_MUTATION_ORIGINAL_CORPUS_ENTRY";
    size_t pre_len = strlen(pre_mut);
    memcpy(parent_input, pre_mut, pre_len);
    atomic_store(&parent_fb->postMutInputLen, 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        uint8_t *child_input = mmap(
            NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
        assert(child_input != MAP_FAILED);

        shared_feedback_t *child_fb = mmap(
            NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
        assert(child_fb != MAP_FAILED);

        /* Step 1: Custom mutator runs (writeback happens) */
        const char *mutated = "MUTATED_DATA_AFTER_CUSTOM_MUTATOR";
        size_t mut_len = strlen(mutated);
        memcpy(child_input, mutated, mut_len);
        atomic_store(&child_fb->postMutInputLen, mut_len);

        /* Step 2: Crossover runs and produces DIFFERENT data.
           This simulates LLVMFuzzerCustomCrossOver merging the mutated
           input with a donor from the ring buffer. */
        uint8_t xo_buf[INPUT_MAX_SIZE];
        const char *crossed = "CROSSOVER_MERGED_PROTOBUF_CRASH_TRIGGER";
        size_t xo_len = strlen(crossed);
        memcpy(xo_buf, crossed, xo_len);

        /* Crossover writeback (the fix we're adding) */
        memcpy(child_input, xo_buf, xo_len);
        atomic_store(&child_fb->postMutInputLen, xo_len);

        _exit(134);
    }

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 134);

    /* Parent saves crash file */
    save_crash_file(crash_path, parent_input, pre_len, parent_fb, INPUT_MAX_SIZE);

    /* Verify: crash file has crossover output, not mutation output or corpus */
    uint8_t file_buf[INPUT_MAX_SIZE];
    size_t file_len = read_file(crash_path, file_buf, INPUT_MAX_SIZE);

    const char *expected = "CROSSOVER_MERGED_PROTOBUF_CRASH_TRIGGER";
    size_t expected_len = strlen(expected);
    assert(file_len == expected_len);
    assert(memcmp(file_buf, expected, expected_len) == 0);
    assert(memcmp(file_buf, "PRE_MUTATION", 12) != 0);
    assert(memcmp(file_buf, "MUTATED_DATA", 12) != 0);

    munmap(parent_input, INPUT_MAX_SIZE);
    munmap(parent_fb, sizeof(shared_feedback_t));
    close(input_fd);
    close(fb_fd);

    printf("PASS\n");
}

/* -----------------------------------------------------------------------
   Test 3: No writeback (old behavior) → crash file has WRONG data
   ----------------------------------------------------------------------- */
static void test_no_writeback_saves_wrong_data(const char *crash_path) {
    printf("TEST: without writeback, crash file has pre-mutation data ... ");

    int input_fd = memfd_create("hf_input_nofix", 0);
    assert(input_fd >= 0);
    assert(ftruncate(input_fd, INPUT_MAX_SIZE) == 0);

    int fb_fd = memfd_create("hf_fb_nofix", 0);
    assert(fb_fd >= 0);
    assert(ftruncate(fb_fd, sizeof(shared_feedback_t)) == 0);

    uint8_t *parent_input = mmap(
        NULL, INPUT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, input_fd, 0);
    assert(parent_input != MAP_FAILED);

    shared_feedback_t *parent_fb = mmap(
        NULL, sizeof(shared_feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    assert(parent_fb != MAP_FAILED);

    const char *pre_mut = "PRE_MUTATION_CORPUS_DATA";
    size_t pre_len = strlen(pre_mut);
    memcpy(parent_input, pre_mut, pre_len);
    atomic_store(&parent_fb->postMutInputLen, 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        /* Old behavior: child maps read-only, no writeback */
        uint8_t *child_input = mmap(
            NULL, INPUT_MAX_SIZE, PROT_READ, MAP_SHARED, input_fd, 0);
        assert(child_input != MAP_FAILED);

        /* Mutation happens in local buffer only */
        uint8_t mut_buf[INPUT_MAX_SIZE];
        memcpy(mut_buf, child_input, pre_len);
        const char *post_mut = "POST_MUTATION_CRASH_TRIGGER";
        memcpy(mut_buf, post_mut, strlen(post_mut));
        /* No writeback, no postMutInputLen update */

        _exit(134);
    }

    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 134);

    /* Parent saves crash file — postMutInputLen is 0, falls back to
       dynfile_size which is the pre-mutation length */
    save_crash_file(crash_path, parent_input, pre_len, parent_fb, INPUT_MAX_SIZE);

    /* BUG: crash file contains pre-mutation data — would NOT reproduce! */
    uint8_t file_buf[INPUT_MAX_SIZE];
    size_t file_len = read_file(crash_path, file_buf, INPUT_MAX_SIZE);

    assert(file_len == pre_len);
    assert(memcmp(file_buf, "PRE_MUTATION", 12) == 0);
    assert(memcmp(file_buf, "POST_MUTATION", 13) != 0);

    munmap(parent_input, INPUT_MAX_SIZE);
    munmap(parent_fb, sizeof(shared_feedback_t));
    close(input_fd);
    close(fb_fd);

    printf("PASS (demonstrates the bug this fix addresses)\n");
}

int main(void) {
    printf("=== Post-mutation writeback crash persistence tests ===\n\n");

    char crash_path[] = "/tmp/hf_test_crash_XXXXXX";
    int tmp_fd = mkstemp(crash_path);
    assert(tmp_fd >= 0);
    close(tmp_fd);

    test_mutation_crash_file_has_postmut_data(crash_path);
    test_crossover_crash_file_has_postmut_data(crash_path);
    test_no_writeback_saves_wrong_data(crash_path);

    unlink(crash_path);

    printf("\nAll tests passed.\n");
    return 0;
}
