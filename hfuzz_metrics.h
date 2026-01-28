#ifndef _HF_METRICS_H_
#define _HF_METRICS_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize metrics session at fuzzer startup.
 * Called from honggfuzz main() after threads are started.
 *
 * target_name: name of the fuzz target binary
 * argc/argv: command line arguments
 */
void hfuzz_metrics_session_init(const char* target_name, int argc, char** argv);

/*
 * Finalize metrics session at fuzzer shutdown.
 * Called from honggfuzz main() after mainThreadLoop() returns.
 *
 * status: "completed", "interrupted", or "crashed"
 * executions: total number of executions
 * crashes: total number of crashes detected
 * hangs: total number of hangs/timeouts detected
 * cpu_seconds: total CPU time used
 * memory_peak_mb: peak memory usage in MB
 */
void hfuzz_metrics_session_end(const char* status, 
                                uint64_t executions,
                                uint64_t crashes, 
                                uint64_t hangs,
                                uint64_t cpu_seconds,
                                uint64_t memory_peak_mb);

/*
 * Log a single execution completion.
 * Called from fuzz_fuzzLoop() after each execution.
 * Implementations should use time-based batching to avoid overhead.
 *
 * input_size: size of the input in bytes
 * exec_time_us: execution time in microseconds
 */
void hfuzz_metrics_log_execution(size_t input_size, uint64_t exec_time_us);

/*
 * Log a crash detection.
 * Called from linux/trace.c (or platform equivalent) after crashesCnt++.
 *
 * description: crash description string (signal, address, etc.)
 * backtrace_hash: unique hash of the crash backtrace
 * input_size: size of the crashing input
 */
void hfuzz_metrics_log_crash(const char* description, 
                              uint64_t backtrace_hash,
                              size_t input_size);

/*
 * Log a hang/timeout detection.
 * Called from subproc.c after timeoutedCnt++.
 *
 * input_size: size of the hanging input
 * timeout_ms: timeout threshold in milliseconds
 */
void hfuzz_metrics_log_hang(size_t input_size, uint64_t timeout_ms);

/*
 * Log coverage metrics update.
 * Called from fuzz_perfFeedback() when coverage increases.
 *
 * new_pcs: new program counters discovered this execution
 * new_edges: new edges discovered this execution
 * new_cmp: new comparison progress this execution
 * total_pcs: cumulative total PCs covered
 * total_edges: cumulative total edges covered
 * total_cmp: cumulative comparison progress
 * corpus_count: number of inputs in the corpus
 */
void hfuzz_metrics_log_coverage(uint64_t new_pcs, 
                                 uint64_t new_edges,
                                 uint64_t new_cmp, 
                                 uint64_t total_pcs,
                                 uint64_t total_edges, 
                                 uint64_t total_cmp,
                                 size_t corpus_count);

/*
 * Set the coverage denominator (total possible coverage points).
 * Called during initialization after PC guards are set up.
 *
 * total_guards: total number of PC guards instrumented
 */
void hfuzz_metrics_set_coverage_denominator(uint64_t total_guards);

/*
 * Log detailed coverage map for source-level analysis.
 * Called periodically to enable file/function/line coverage tracking.
 *
 * guard_map: pointer to the PC guard hit count map
 * guard_count: number of guards in the map
 * 
 * The implementation can iterate the map to count covered guards
 * and use symbolization to map to source locations.
 */
void hfuzz_metrics_log_detailed_coverage(const uint8_t* guard_map, 
                                          uint64_t guard_count);

/*
 * Notify metrics of a newly instrumented module for coverage tracking.
 * Called from __sanitizer_cov_trace_pc_guard_init for each module.
 *
 * module_name: path/name of the instrumented module
 * guard_start: starting guard number for this module
 * guard_count: number of guards in this module
 */
void hfuzz_metrics_register_module(const char* module_name,
                                    uint32_t guard_start,
                                    uint32_t guard_count);

/*
 * PC table entry as provided by __sanitizer_cov_pcs_init.
 * Each entry contains the PC address and flags (is_function_entry).
 */
typedef struct {
    uintptr_t pc;
    uintptr_t flags;  /* 1 = function entry, 0 = basic block */
} hfuzz_pc_entry_t;

/*
 * Register PC table for a module (called from __sanitizer_cov_pcs_init).
 * This provides the actual PC addresses that can be symbolized to source locations.
 *
 * module_name: path/name of the instrumented module  
 * pcs: array of PC entries (address + flags pairs)
 * pc_count: number of entries in the table
 * guard_start: starting guard number for this module (to correlate with guard map)
 *
 * The PC table entries correspond 1:1 with guards, allowing us to map
 * guard[i] -> pcs[i - guard_start] -> symbolized source location.
 */
void hfuzz_metrics_register_pc_table(const char* module_name,
                                      const hfuzz_pc_entry_t* pcs,
                                      size_t pc_count,
                                      uint32_t guard_start);

/*
 * Log full coverage report with both covered and uncovered locations.
 * Uses the registered PC tables to symbolize all guards.
 *
 * guard_map: pointer to the PC guard hit count map
 * guard_count: number of guards in the map
 * output_path: path to write JSON coverage report (NULL for ClickHouse only)
 */
void hfuzz_metrics_log_full_coverage_report(const uint8_t* guard_map,
                                             uint64_t guard_count,
                                             const char* output_path);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _HF_METRICS_H_ */

