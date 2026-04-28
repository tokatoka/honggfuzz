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

/*
 * Register the shared coverage feedback pointers for live monitoring.
 * This starts a background thread that periodically snapshots coverage
 * and logs newly-covered guards to ClickHouse with symbolization.
 *
 * guard_map: pointer to the pcGuardMap (8-bit counters per guard)
 * guard_count_ptr: pointer to the atomic guard count (feedback_t.guardNb)
 *
 * The background thread:
 * - Runs every 60 seconds (configurable)
 * - Compares current coverage to previous snapshot
 * - Symbolizes newly-covered guards (cached for efficiency)
 * - Logs all covered guards with hit counts to ClickHouse
 *
 * This enables live coverage visualization with minimal per-execution overhead.
 */
void hfuzz_metrics_register_coverage_feedback(const uint8_t* guard_map,
                                               void* guard_count_ptr);

/*
 * Log comprehensive fuzzer statistics.
 * Called periodically from input.c after the SCHED/DECAY/HEALTH/DIFF-FUZZ-STATS LOG_I calls.
 * Contains all the rich metrics about scheduling, energy decay, health, and differential fuzzing.
 *
 * SCHED-STATS:
 *   sched_total: total scheduling decisions
 *   repeat_pct: percentage of repeated inputs
 *   high_pct: percentage of high-priority selections
 *   low_pct: percentage of low-priority selections
 *   phase2_pct: percentage of phase2 fallback selections
 *   avg_energy: average energy assigned to inputs
 *   avg_iters: average iterations per input
 *   max_iters: maximum iterations seen for any input
 *   energy_min/energy_max: range of energy values
 *
 * DECAY-STATS:
 *   novelty_decay: count of novelty decay applications
 *   fresh_boost: count of fresh input boosts
 *   stale_penalty: count of stale input penalties
 *   diminishing: count of diminishing returns penalties
 *   depth_penalty: count of depth-based penalties
 *   corpus_count: current corpus size (number of inputs)
 *   global_avg_energy: global average energy
 *
 * HEALTH-STATS:
 *   exec_avg_us: average execution time in microseconds
 *   exec_max_us: maximum execution time in microseconds
 *   slow_execs: count of slow executions
 *   mut_hit_rate_pct: mutation hit rate percentage (mutations that found new coverage)
 *   plateau_secs: seconds since last new coverage (coverage plateau)
 *   queue_wraps: number of times corpus queue wrapped
 *   max_depth: maximum mutation depth in corpus
 *
 * DIFF-FUZZ-STATS:
 *   unique_crashes: count of unique crashes
 *   total_crashes: total crash count
 *   timeouts: count of timeouts
 *   fertile_boosts: differential fuzzing fertile lineage boosts
 *   saturated: count of saturated lineages
 *   explore_selects: exploration mode selections
 *   secs_since_crash: seconds since last crash
 *   stagnation_secs: seconds of coverage stagnation
 *   corpus_growth: corpus inputs added since last log
 *
 * INPUT-HEALTH:
 *   inputs_truncated_too_large: count of inputs truncated because they exceeded maxFileSz/maxInputSz
 */
void hfuzz_metrics_log_stats(
    /* EXECUTION COUNT (for timeseries rate calculation) */
    uint64_t total_executions,
    /* COVERAGE METRICS (for complete timeseries data) */
    uint64_t coverage_pcs,
    uint64_t coverage_edges,
    uint64_t coverage_cmp,
    uint64_t coverage_edge_bucket,
    /* SCHED-STATS */
    uint64_t sched_total,
    float repeat_pct,
    float high_pct,
    float low_pct,
    float phase2_pct,
    uint64_t avg_energy,
    float avg_iters,
    uint64_t max_iters,
    uint64_t energy_min,
    uint64_t energy_max,
    /* DECAY-STATS */
    uint64_t novelty_decay,
    uint64_t fresh_boost,
    uint64_t stale_penalty,
    uint64_t diminishing,
    uint64_t depth_penalty,
    uint64_t corpus_count,
    uint64_t global_avg_energy,
    /* HEALTH-STATS */
    uint64_t exec_avg_us,
    uint64_t exec_max_us,
    uint64_t slow_execs,
    float mut_hit_rate_pct,
    uint64_t plateau_secs,
    uint64_t queue_wraps,
    uint32_t max_depth,
    /* DIFF-FUZZ-STATS */
    uint64_t unique_crashes,
    uint64_t total_crashes,
    uint64_t timeouts,
    uint64_t fertile_boosts,
    uint64_t saturated,
    uint64_t explore_selects,
    uint64_t secs_since_crash,
    uint64_t stagnation_secs,
    uint64_t corpus_growth,
    const char* fuzzer_state,
    uint64_t dry_run_tested,
    uint64_t dry_run_total,
    /* INPUT-HEALTH */
    uint64_t inputs_truncated_too_large
);

/*
 * Log mutation pipeline health metrics.
 * Called periodically alongside hfuzz_metrics_log_stats() to track whether
 * the protobuf mutation pipeline is functional.
 *
 * total_executions:         Cumulative execution counter (same source as log_stats)
 * proto_parse_calls:        Total LLVMFuzzerTestOneInput invocations
 * proto_parse_successes:    Calls where LoadProtoInput returned true
 * custom_mutator_calls:     LLVMFuzzerCustomMutator invocations
 * custom_mutator_successes: Custom mutator calls that returned >0 bytes
 * proto_round_cnt:          mangle_mangleContent rounds using proto-aware mutation
 * proto_scan_ok_cnt:        proto_scan_fields calls that found >= 1 field
 * total_round_cnt:          Total mangle_mangleContent calls
 * kutator_mutate_cnt:       Kutator LLVMFuzzerCustomMutator invocations
 * kutator_crossover_cnt:    Kutator LLVMFuzzerCustomCrossOver invocations
 * kutator_parse_success_cnt: Kutator protobuf parse successes
 * kutator_parse_fail_cnt:   Kutator protobuf parse failures
 * encode_overflow_cnt:      Mutations that exceeded the output buffer size
 * no_candidates_cnt:        Mutations where no candidate fields were found
 * kind_counts:              Per-MutationKind counters (array, kind_num entries)
 * kind_names:               Per-MutationKind display names (array, kind_num entries, may contain NULL)
 * kind_num:                 Number of MutationKind variants (length of kind_counts/kind_names)
 * _elf_fixup_ok_cnt:        (unused, kept for ABI compat)
 * exec_fail_cnt:            Harness executions that returned failure
 * verify_cnt:               Crash verification attempts
 * harness_reject_cnt:       Inputs rejected by harness (any executor failed)
 */
void hfuzz_metrics_log_mutation_health(
    uint64_t total_executions,
    uint64_t proto_parse_calls,
    uint64_t proto_parse_successes,
    uint64_t custom_mutator_calls,
    uint64_t custom_mutator_successes,
    uint64_t proto_round_cnt,
    uint64_t proto_scan_ok_cnt,
    uint64_t total_round_cnt,
    uint64_t kutator_mutate_cnt,
    uint64_t kutator_crossover_cnt,
    uint64_t kutator_parse_success_cnt,
    uint64_t kutator_parse_fail_cnt,
    uint64_t encode_overflow_cnt,
    uint64_t no_candidates_cnt,
    const uint64_t* kind_counts,
    const char* const* kind_names,
    uint32_t kind_num,
    uint64_t _elf_fixup_ok_cnt,
    uint64_t exec_fail_cnt,
    uint64_t verify_cnt,
    uint64_t harness_reject_cnt
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _HF_METRICS_H_ */

