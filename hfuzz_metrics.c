#include "hfuzz_metrics.h"

#include "libhfcommon/common.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>

/*
 * Runtime resolution for metrics functions.
 *
 * The metrics bridge library (libhfuzz_metrics_bridge.so) provides the real
 * implementations. We use dlsym at runtime to find them, which works with
 * LD_PRELOAD or when the library is linked with -Wl,--no-as-needed.
 *
 * If the bridge library isn't loaded, all functions are no-ops.
 */

/* Function pointer types */
typedef void (*session_init_fn)(const char*, int, char**);
typedef void (*session_end_fn)(const char*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef void (*log_execution_fn)(size_t, uint64_t);
typedef void (*log_crash_fn)(const char*, uint64_t, size_t);
typedef void (*log_hang_fn)(size_t, uint64_t);
typedef void (*log_coverage_fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, size_t);
typedef void (*log_detailed_coverage_fn)(const uint8_t*, uint64_t);
typedef void (*register_module_fn)(const char*, uint64_t, uint64_t);
typedef void (*register_pc_table_fn)(const char*, const hfuzz_pc_entry_t*, size_t, uint64_t);
typedef void (*log_full_coverage_fn)(const uint8_t*, uint64_t, const char*);
typedef void (*register_coverage_feedback_fn)(const uint8_t*, void*);
typedef void (*log_mutation_health_fn)(
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,  /* total_execs, pp_calls, pp_succ, cm_calls, cm_succ */
    uint64_t, uint64_t, uint64_t,                       /* proto_round, proto_scan, total_round */
    uint64_t, uint64_t, uint64_t, uint64_t,             /* kutator_mutate, kutator_xover, kutator_parse_ok, kutator_parse_fail */
    uint64_t, uint64_t,                                 /* encode_overflow, no_candidates */
    const uint64_t*, const char* const*, uint32_t,      /* kind_counts, kind_names, kind_num */
    uint64_t, uint64_t, uint64_t,                       /* _elf_fixup_ok (unused), exec_fail, verify */
    uint64_t                                            /* harness_reject */
);
typedef void (*log_stats_fn)(
    uint64_t, /* total_executions */
    uint64_t, uint64_t, uint64_t, uint64_t, /* coverage_pcs, coverage_edges, coverage_cmp, coverage_edge_bucket */
    uint64_t, float, float, float, float, uint64_t, float, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, float, uint64_t, uint64_t, uint32_t,
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    const char*, /* fuzzer_state */
    uint64_t, uint64_t, /* dry_run_tested, dry_run_total */
    uint64_t  /* inputs_truncated_too_large */
);

/* Resolved function pointers */
static session_init_fn         fn_session_init = NULL;
static session_end_fn          fn_session_end = NULL;
static log_execution_fn        fn_log_execution = NULL;
static log_crash_fn            fn_log_crash = NULL;
static log_hang_fn             fn_log_hang = NULL;
static log_coverage_fn         fn_log_coverage = NULL;
static log_detailed_coverage_fn fn_log_detailed_coverage = NULL;
static register_module_fn      fn_register_module = NULL;
static register_pc_table_fn    fn_register_pc_table = NULL;
static log_full_coverage_fn    fn_log_full_coverage = NULL;
static register_coverage_feedback_fn fn_register_coverage_feedback = NULL;
static log_mutation_health_fn  fn_log_mutation_health = NULL;
static log_stats_fn            fn_log_stats = NULL;

static bool s_resolved = false;

/*
 * Resolve function pointers from the metrics bridge library at runtime.
 * Uses dlsym(RTLD_DEFAULT, ...) to find symbols in any loaded library.
 */
static void resolve_metrics_functions(void) {
    if (s_resolved) return;
    s_resolved = true;

    fprintf(stderr, "[hfuzz_metrics] Resolving metrics bridge symbols via dlsym...\n");

    /* Look for the bridge library's implementations */
    fn_session_init = (session_init_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_session_init");
    fn_session_end = (session_end_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_session_end");
    fn_log_execution = (log_execution_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_log_execution");
    fn_log_crash = (log_crash_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_log_crash");
    fn_log_hang = (log_hang_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_log_hang");
    fn_log_coverage = (log_coverage_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_log_coverage");
    fn_log_detailed_coverage = (log_detailed_coverage_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_log_detailed_coverage");
    fn_register_module = (register_module_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_register_module");
    fn_register_pc_table = (register_pc_table_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_register_pc_table");
    fn_log_full_coverage = (log_full_coverage_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_log_full_coverage_report");
    fn_register_coverage_feedback = (register_coverage_feedback_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_register_coverage_feedback");
    fn_log_mutation_health = (log_mutation_health_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_log_mutation_health");
    fn_log_stats = (log_stats_fn)dlsym(RTLD_DEFAULT, "hfuzz_metrics_bridge_log_stats");

    if (fn_session_init) {
        fprintf(stderr, "[hfuzz_metrics] Found metrics bridge library, metrics enabled\n");
        if (!fn_log_stats) {
            fprintf(stderr, "[hfuzz_metrics] WARNING: fn_log_stats not resolved -- "
                    "execution_events will NOT be written to ClickHouse\n");
        }
    } else {
        /* Check if the bridge library was loaded but symbols not found */
        void* bridge_lib = dlopen("libhfuzz_metrics_bridge.so", RTLD_NOLOAD | RTLD_LAZY);
        if (bridge_lib) {
            fprintf(stderr, "[hfuzz_metrics] Metrics bridge library loaded but symbols not found (version mismatch?)\n");
            dlclose(bridge_lib);
        } else {
            fprintf(stderr, "[hfuzz_metrics] Metrics bridge library not loaded, metrics disabled (this is OK)\n");
        }
    }
}

/* Public API - these call through function pointers resolved at runtime */

void hfuzz_metrics_session_init(const char* target_name, int argc, char** argv) {
    resolve_metrics_functions();
    if (fn_session_init) fn_session_init(target_name, argc, argv);
}

void hfuzz_metrics_session_end(const char* status,
                                uint64_t executions,
                                uint64_t crashes,
                                uint64_t hangs,
                                uint64_t cpu_seconds,
                                uint64_t memory_peak_mb) {
    if (fn_session_end) fn_session_end(status, executions, crashes, hangs, cpu_seconds, memory_peak_mb);
}

void hfuzz_metrics_log_execution(size_t input_size, uint64_t exec_time_us) {
    if (fn_log_execution) fn_log_execution(input_size, exec_time_us);
}

void hfuzz_metrics_log_crash(const char* description,
                              uint64_t backtrace_hash,
                              size_t input_size) {
    if (fn_log_crash) fn_log_crash(description, backtrace_hash, input_size);
}

void hfuzz_metrics_log_hang(size_t input_size, uint64_t timeout_ms) {
    if (fn_log_hang) fn_log_hang(input_size, timeout_ms);
}

void hfuzz_metrics_log_coverage(uint64_t new_pcs,
                                 uint64_t new_edges,
                                 uint64_t new_cmp,
                                 uint64_t total_pcs,
                                 uint64_t total_edges,
                                 uint64_t total_cmp,
                                 size_t corpus_count) {
    if (fn_log_coverage) fn_log_coverage(new_pcs, new_edges, new_cmp, total_pcs, total_edges, total_cmp, corpus_count);
}

void hfuzz_metrics_log_detailed_coverage(const uint8_t* guard_map, uint64_t guard_count) {
    if (fn_log_detailed_coverage) fn_log_detailed_coverage(guard_map, guard_count);
}

void hfuzz_metrics_register_module(const char* module_name,
                                    uint32_t guard_start,
                                    uint32_t guard_count) {
    resolve_metrics_functions();
    if (fn_register_module) fn_register_module(module_name, guard_start, guard_count);
}

void hfuzz_metrics_register_pc_table(const char* module_name,
                                      const hfuzz_pc_entry_t* pcs,
                                      size_t pc_count,
                                      uint32_t guard_start) {
    resolve_metrics_functions();
    if (fn_register_pc_table) {
        fn_register_pc_table(module_name, pcs, pc_count, guard_start);
    }
}

void hfuzz_metrics_log_full_coverage_report(const uint8_t* guard_map,
                                             uint64_t guard_count,
                                             const char* output_path) {
    if (fn_log_full_coverage) fn_log_full_coverage(guard_map, guard_count, output_path);
}

void hfuzz_metrics_register_coverage_feedback(const uint8_t* guard_map,
                                               void* guard_count_ptr) {
    if (fn_register_coverage_feedback) fn_register_coverage_feedback(guard_map, guard_count_ptr);
}

void hfuzz_metrics_log_stats(
    /* EXECUTION COUNT */
    uint64_t total_executions,
    /* COVERAGE METRICS */
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
) {
    if (fn_log_stats) {
        fn_log_stats(
            total_executions,
            coverage_pcs, coverage_edges, coverage_cmp, coverage_edge_bucket,
            sched_total, repeat_pct, high_pct, low_pct, phase2_pct, avg_energy, avg_iters, max_iters, energy_min, energy_max,
            novelty_decay, fresh_boost, stale_penalty, diminishing, depth_penalty, corpus_count, global_avg_energy,
            exec_avg_us, exec_max_us, slow_execs, mut_hit_rate_pct, plateau_secs, queue_wraps, max_depth,
            unique_crashes, total_crashes, timeouts, fertile_boosts, saturated, explore_selects, secs_since_crash, stagnation_secs, corpus_growth,
            fuzzer_state, dry_run_tested, dry_run_total,
            inputs_truncated_too_large
        );
    } else {
        static bool warned = false;
        if (!warned) {
            warned = true;
            fprintf(stderr, "[hfuzz_metrics] WARNING: hfuzz_metrics_log_stats called but "
                    "fn_log_stats is NULL (bridge not loaded in this process?)\n");
        }
    }
}

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
) {
    if (fn_log_mutation_health) {
        fn_log_mutation_health(total_executions,
                               proto_parse_calls, proto_parse_successes,
                               custom_mutator_calls, custom_mutator_successes,
                               proto_round_cnt, proto_scan_ok_cnt, total_round_cnt,
                               kutator_mutate_cnt, kutator_crossover_cnt, kutator_parse_success_cnt, kutator_parse_fail_cnt,
                               encode_overflow_cnt, no_candidates_cnt,
                               kind_counts, kind_names, kind_num,
                               _elf_fixup_ok_cnt, exec_fail_cnt, verify_cnt, harness_reject_cnt);
    }
}

