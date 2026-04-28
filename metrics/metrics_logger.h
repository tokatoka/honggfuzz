#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <atomic>
#include <tuple>
#include "jsonl_writer.h"

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <set>
#endif

namespace sol_compat {

class MetricsLogger {
public:
    static MetricsLogger& instance();

    void init(
        const std::string& session_id,
        const std::string& fuzzer_name,
        const std::string& harness_name,
        const std::string& fuzz_target,
        const std::vector<std::string>& target_names,
        const std::vector<std::string>& target_paths,
        const std::string& program_id,
        const std::string& syscall_name,
        const std::string& user_name,
        const std::string& host_name,
        const std::string& task_id,
        const std::string& bundle_id,
        const std::string& asset_id,
        const std::string& organization,
        const std::string& project,
        const std::string& lineage_name,
        const std::string& corpus_group,
        const std::string& task_type);
    
    void log_session_start();
    
    void log_session_end(
        const std::string& status,
        uint64_t total_executions,
        uint64_t total_crashes,
        uint64_t total_hangs,
        float cpu_hours,
        uint64_t memory_peak_mb,
        uint64_t corpus_size);

    void log_execution_metrics(
        uint64_t total_executions,
        uint64_t total_crashes,
        uint64_t total_hangs,
        float cpu_usage,
        uint64_t memory_usage_mb,
        uint64_t corpus_size,
        float corpus_diversity_score,
        uint64_t total_mutations_executed = 0,
        uint64_t total_mutations_successful = 0,
        float mutation_success_rate = 0.0f,
        uint64_t new_features_discovered = 0);

    // Log comprehensive fuzzer stats (SCHED/DECAY/HEALTH/DIFF-FUZZ stats)
    void log_fuzzer_stats(
        // EXECUTION COUNT (for timeseries rate calculation)
        uint64_t total_executions,
        // COVERAGE METRICS (for complete timeseries data)
        uint64_t coverage_pcs,
        uint64_t coverage_edges,
        uint64_t coverage_cmp,
        uint64_t coverage_edge_bucket,
        // SCHED-STATS
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
        // DECAY-STATS
        uint64_t novelty_decay,
        uint64_t fresh_boost,
        uint64_t stale_penalty,
        uint64_t diminishing,
        uint64_t depth_penalty,
        uint64_t corpus_count,
        uint64_t global_avg_energy,
        // HEALTH-STATS
        uint64_t exec_avg_us,
        uint64_t exec_max_us,
        uint64_t slow_execs,
        float mut_hit_rate_pct,
        uint64_t plateau_secs,
        uint64_t queue_wraps,
        uint32_t max_depth,
        // DIFF-FUZZ-STATS
        uint64_t unique_crashes,
        uint64_t total_crashes,
        uint64_t timeouts,
        uint64_t fertile_boosts,
        uint64_t saturated,
        uint64_t explore_selects,
        uint64_t secs_since_crash,
        uint64_t stagnation_secs,
        uint64_t corpus_growth,
        const std::string& fuzzer_state = "unknown",
        uint64_t dry_run_tested = 0,
        uint64_t dry_run_total = 0,
        // INPUT-HEALTH
        uint64_t inputs_truncated_too_large = 0);

    // Log mutation health metrics (proto/kutator counters)
    void log_mutation_health(
        uint64_t total_executions,
        uint64_t proto_parse_calls,
        uint64_t proto_parse_successes,
        uint64_t custom_mutator_calls,
        uint64_t custom_mutator_successes,
        float rate,
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
        uint64_t harness_reject_cnt);

    void log_bug_discovery(
        const std::string& bug_id,
        const std::string& fuzzer_name,
        const std::string& file,
        const std::string& function,
        int line,
        const std::string& bug_type,
        const std::string& severity,
        const std::string& status,
        uint64_t reproduction_time_ms,
        size_t input_size,
        const std::string& description);

    // Log a differential fuzzing mismatch between expected and actual outcomes
    void log_mismatch(
        const std::string& category,
        const std::string& expected,
        const std::string& actual,
        const std::string& details);

    // Coverage event: one row per function with a range of lines and hits.
    void log_coverage_event(
        const std::string& component,
        const std::string& file_path,
        const std::string& function_name,
        uint32_t start_line,
        uint32_t end_line,
        const std::string& coverage_type,
        uint64_t hits,
        const std::vector<uint32_t>& line_numbers = {},
        const std::vector<uint32_t>& line_hits = {},
        const std::string& target_name = "");

    // Batched insert for coverage events
    void log_coverage_events_batch(
        const std::string& component,
        const std::vector<std::tuple<
            std::string,   // file_path
            std::string,   // function_name
            uint32_t,      // start_line
            uint32_t,      // end_line
            std::string,   // coverage_type
            uint64_t,      // hits
            std::vector<uint32_t>, // line_numbers
            std::vector<uint32_t>  // line_hits
        >>& events,
        const std::string& target_name = "");

    // Log coverage per execution, tracking which methods/lines are covered in each execution
    // This allows queries like "what fraction of executions covered method X"
    void log_execution_coverage(
        uint64_t execution_id,
        const std::string& component,
        const std::vector<std::tuple<
            std::string,   // file_path
            std::string,   // function_name
            uint32_t,      // start_line
            uint32_t,      // end_line
            std::string    // coverage_type
        >>& covered_items);

    // Guard first-hit event for efficient coverage tracking
    // Only stores WHEN each guard was first covered (event-sourced approach)
    struct GuardFirstHitEntry {
        uint64_t guard_id;
        std::string file_path;
        std::string function_name;
        uint32_t line_number;
        std::string module_name;
        std::string coverage_type;  // "function" or "block"
    };

    // Log batch of guard first-hit events (event-sourced coverage)
    // This is the efficient approach: only log NEWLY covered guards, not all covered guards.
    // Combined with PC Guard Registry, this allows reconstruction of full coverage state.
    void log_guard_first_hits(const std::vector<GuardFirstHitEntry>& entries);

    // Mark logger as shutting down to prevent reconnection attempts
    void set_shutting_down(bool shutting_down = true);
    
    // Ensure connection is alive before logging
    void ensure_connection();
    
    // Wait for async logging queue to drain (called during shutdown)
    void wait_for_queue_drain_();

private:
    // Common session event logging helper
    void log_session_event(
        const std::string& event_type,
        const std::string& status = "",
        uint64_t total_executions = 0,
        uint64_t total_crashes = 0,
        uint64_t total_hangs = 0,
        float cpu_hours = 0.0,
        uint64_t memory_peak_mb = 0,
        uint64_t corpus_size = 0);

protected:
    MetricsLogger();   // Defined in .cxx where ClickHouseClient is complete
    ~MetricsLogger();  // Defined in .cxx where ClickHouseClient is complete
    static MetricsLogger* s_instance;

    // ClickHouse (clickhouse-cpp) client config
    struct CHConfig {
        std::string host;
        uint16_t    port = 9000;
        bool        secure = false;
        std::string database;
        std::string user;
        std::string password;
        bool        enabled = false;
    } ch_;
    friend class ClickHouseClient;

    // Context state
    std::string session_id_;
    std::string fuzzer_name_;
    std::string harness_name_;
    std::string fuzz_target_;
    std::vector<std::string> target_names_;
    std::vector<std::string> target_paths_;
    std::string program_id_;
    std::string syscall_name_;
    std::string user_name_;
    std::string host_name_;

    // Environment variables
    std::string task_id_;
    std::string bundle_id_;
    std::string asset_id_;
    std::string organization_;
    std::string project_;
    std::string lineage_name_;
    std::string corpus_group_;
    std::string task_type_;

    // execs_delta tracking (previous total_executions for delta computation)
    std::atomic<uint64_t> prev_total_executions_{0};

    // Shutdown status
    std::atomic<bool> m_shutting_down{false};

    // Vector JSONL output (works without SOLFUZZ_CLICKHOUSE_ENABLED)
    JsonlSink vector_sink_;
    std::atomic<bool> vector_enabled_{false};
    void add_common_fields_(JsonBuilder& jb);
    void emit_jsonl_(const std::string& table, JsonBuilder& jb);

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    // Async DB logging infrastructure
    std::thread m_logger_thread;
    std::queue<std::function<void()>> m_log_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    std::atomic<bool> m_logger_running{false};
    static constexpr size_t MAX_QUEUE_SIZE = 10000; // cap queue size

    // Internal ClickHouseDB helpers
    static int64_t now_epoch_ms_(); // ms since UNIX time epoch for DateTime64(3)
    void create_client_and_tables_(); // Called once from init() on main thread
    void ensure_client_();           // For reconnection only - does NOT create tables
    void ensure_client_unlocked_();  // Same, but caller must hold m_client_mutex
    void ensure_tables_();  // Called only from create_client_and_tables_()
    void reconnect_if_needed_();
    bool insert_with_retry_(const std::string& table_name, void* block_ptr, const std::string& operation_desc);
    void logger_thread_func_();
    void enqueue_log_(std::function<void()> task, const std::string& operation_desc);
    void enqueue_insert_(const std::string& table_name, void* block_ptr, const std::string& operation_desc);
    void append_common_columns_to_block_(void* block_ptr);
    std::unique_ptr<class ClickHouseClient> client_;
    mutable std::mutex m_client_mutex; // Protects client_ access
    std::atomic<bool> m_tables_initialized{false}; // Tables created once on main thread
    std::set<std::string> ensured_kind_columns_; // Kind columns already ALTER-ed into execution_events
    void ensure_kind_columns_(const char* const* kind_names, uint32_t kind_num);
#endif
};

} // namespace sol_compat
