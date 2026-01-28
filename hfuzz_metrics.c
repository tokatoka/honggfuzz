#include "hfuzz_metrics.h"

#include "libhfcommon/common.h"

/*
 * All functions are marked weak so they can be overridden at link time.
 * The default implementations are no-ops with zero overhead.
 */

__attribute__((weak)) 
void hfuzz_metrics_session_init(const char* target_name HF_ATTR_UNUSED, 
                                 int argc HF_ATTR_UNUSED, 
                                 char** argv HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak)) 
void hfuzz_metrics_session_end(const char* status HF_ATTR_UNUSED,
                                uint64_t executions HF_ATTR_UNUSED,
                                uint64_t crashes HF_ATTR_UNUSED,
                                uint64_t hangs HF_ATTR_UNUSED,
                                uint64_t cpu_seconds HF_ATTR_UNUSED,
                                uint64_t memory_peak_mb HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak)) 
void hfuzz_metrics_log_execution(size_t input_size HF_ATTR_UNUSED,
                                  uint64_t exec_time_us HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak)) 
void hfuzz_metrics_log_crash(const char* description HF_ATTR_UNUSED,
                              uint64_t backtrace_hash HF_ATTR_UNUSED,
                              size_t input_size HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak)) 
void hfuzz_metrics_log_hang(size_t input_size HF_ATTR_UNUSED,
                             uint64_t timeout_ms HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak)) 
void hfuzz_metrics_log_coverage(uint64_t new_pcs HF_ATTR_UNUSED,
                                 uint64_t new_edges HF_ATTR_UNUSED,
                                 uint64_t new_cmp HF_ATTR_UNUSED,
                                 uint64_t total_pcs HF_ATTR_UNUSED,
                                 uint64_t total_edges HF_ATTR_UNUSED,
                                 uint64_t total_cmp HF_ATTR_UNUSED,
                                 size_t corpus_count HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak))
void hfuzz_metrics_set_coverage_denominator(uint64_t total_guards HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak))
void hfuzz_metrics_log_detailed_coverage(const uint8_t* guard_map HF_ATTR_UNUSED,
                                          uint64_t guard_count HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak))
void hfuzz_metrics_register_module(const char* module_name HF_ATTR_UNUSED,
                                    uint32_t guard_start HF_ATTR_UNUSED,
                                    uint32_t guard_count HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak))
void hfuzz_metrics_register_pc_table(const char* module_name HF_ATTR_UNUSED,
                                      const hfuzz_pc_entry_t* pcs HF_ATTR_UNUSED,
                                      size_t pc_count HF_ATTR_UNUSED,
                                      uint32_t guard_start HF_ATTR_UNUSED) {
    /* No-op by default */
}

__attribute__((weak))
void hfuzz_metrics_log_full_coverage_report(const uint8_t* guard_map HF_ATTR_UNUSED,
                                             uint64_t guard_count HF_ATTR_UNUSED,
                                             const char* output_path HF_ATTR_UNUSED) {
    /* No-op by default */
}

