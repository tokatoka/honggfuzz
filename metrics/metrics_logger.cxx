#include "metrics_logger.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <cstdlib>
#include <mutex>
#include <unistd.h>

namespace {
static std::string getenv_or(const char* k, const char* dflt) {
    const char* v = std::getenv(k);
    return (v && *v) ? std::string(v) : std::string(dflt);
}

static std::string sanitize_kind_col(const char* raw_name) {
    const char* src = raw_name ? raw_name : "unknown";
    std::string safe;
    for (const char* p = src; *p; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') || *p == '_') {
            safe += *p;
        }
    }
    if (safe.empty()) safe = "unknown";
    return "kind_" + safe + "_cnt";
}
} // namespace

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
#include <chrono>
#include <set>
#include <unistd.h>
#include <pwd.h>
#include <cstring>

// clickhouse-cpp
#include <clickhouse/client.h>
#include <clickhouse/columns/string.h>
#include <clickhouse/columns/array.h>
#include <clickhouse/columns/column.h>
#include <clickhouse/columns/numeric.h>
#include <clickhouse/columns/date.h>
#endif

namespace sol_compat {

// Helper to normalize file paths for consistent coverage tracking.
// Resolves '..' and '.' components so the same file always has the same path.
static std::string normalize_path(const std::string& path) {
    if (path.empty()) {
        return path;
    }
    try {
        std::filesystem::path p(path);
        return p.lexically_normal().string();
    } catch (const std::exception&) {
        return path;
    }
}

MetricsLogger* MetricsLogger::s_instance = nullptr;
static std::once_flag s_instance_once_flag;

MetricsLogger& MetricsLogger::instance() {
    std::call_once(s_instance_once_flag, []() {
        s_instance = new MetricsLogger();
#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
        // Only start background logger thread if ClickHouse is compiled in
        // The thread will only be active if ch_.enabled is true (set in init())
        s_instance->m_logger_running.store(false); // Start as false, will be set to true only if enabled
#endif
    });
    return *s_instance;
}

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
// DB background thread worker
void MetricsLogger::logger_thread_func_() {
    while (m_logger_running.load()) {
        std::function<void()> task;
        
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            // Wait for work or shutdown signal
            m_queue_cv.wait(lock, [this] {
                return !m_log_queue.empty() || !m_logger_running.load();
            });
            
            // If queue is empty and we're shutting down, exit
            if (m_log_queue.empty() && !m_logger_running.load()) {
                break;
            }
            
            // Get task from queue
            if (!m_log_queue.empty()) {
                task = std::move(m_log_queue.front());
                m_log_queue.pop();
            }
        }
        
        // Execute task outside the lock
        if (task) {
            try {
                task();
            } catch (const std::exception& e) {
                std::cerr << "[MetricsLogger] ERROR in async logger thread: " << e.what() << std::endl;
            } catch (...) {
                std::cerr << "[MetricsLogger] ERROR in async logger thread: unknown exception" << std::endl;
            }
        }
    }
    
    // Process any remaining items in queue before exiting
    std::function<void()> task;
    while (true) {
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            if (m_log_queue.empty()) break;
            task = std::move(m_log_queue.front());
            m_log_queue.pop();
        }
        if (task) {
            try {
                task();
            } catch (...) { } // Ignore errors during shutdown
        }
    }
}

// Enqueue a logging task (non-blocking)
void MetricsLogger::enqueue_log_(std::function<void()> task, const std::string& operation_desc) {
    if (!ch_.enabled) {
        return;
    }
    
    // Allow enqueueing even if shutting_down is set, as long as logger thread is still running
    // This ensures items enqueued during shutdown (like coverage events) still get processed
    if (m_shutting_down.load() && !m_logger_running.load()) {
        std::cerr << "[MetricsLogger] WARNING: Rejecting log task '" << operation_desc 
                  << "', DB logger thread already stopped" << std::endl;
        return;
    }
    
    // Could consider removing cap to reduce contention
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        
        // Drop oldest items if queue is full (backpressure)
        if (m_log_queue.size() >= MAX_QUEUE_SIZE) {
            std::cerr << "[MetricsLogger] WARNING: Log queue full (" << MAX_QUEUE_SIZE 
                      << "), dropping oldest entry" << std::endl;
            m_log_queue.pop();
        }
        
        m_log_queue.push(std::move(task));
    }
    
    m_queue_cv.notify_one();
}

// wait_for_queue_drain_() is defined after ClickHouseClient class (requires complete type for client_.reset())

int64_t MetricsLogger::now_epoch_ms_() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// Minimal implementation to avoid leaking clickhouse headers
class ClickHouseClient {
public:
    explicit ClickHouseClient(const MetricsLogger::CHConfig& cfg) {
        clickhouse::ClientOptions opts;
        opts.SetHost(cfg.host);
        opts.SetPort(cfg.port);
        if (!cfg.user.empty()) opts.SetUser(cfg.user);
        if (!cfg.password.empty()) opts.SetPassword(cfg.password);
        if (!cfg.database.empty()) opts.SetDefaultDatabase(cfg.database);
        // Note: SetSecure may not exist in all versions, TLS support may be via different API
        // if (cfg.secure) opts.SetSecure(true);
        opts.SetConnectionRecvTimeout(std::chrono::seconds(10));
        opts.SetConnectionSendTimeout(std::chrono::seconds(10));
        client_ = std::make_unique<clickhouse::Client>(opts);
    }

    clickhouse::Client& c() { return *client_; }

private:
    std::unique_ptr<clickhouse::Client> client_;
};

// Constructor and destructor must be defined here where ClickHouseClient is complete
// (unique_ptr needs complete type for construction and destruction)
MetricsLogger::MetricsLogger() = default;
MetricsLogger::~MetricsLogger() {
    wait_for_queue_drain_();
}

// Wait for queue to drain (called during shutdown)
// Defined here after ClickHouseClient class so client_.reset() has complete type
void MetricsLogger::wait_for_queue_drain_() {
    // Signal no new work should be accepted
    m_shutting_down.store(true);

    // Stop the background thread and wait for it to drain the queue
    if (m_logger_running.exchange(false)) {
        m_queue_cv.notify_one();            // wake thread so it sees the flag
        if (m_logger_thread.joinable()) {
            m_logger_thread.join();
        }
        std::cerr << "[MetricsLogger] Background logger thread joined" << std::endl;
    }

    // Now safe to destroy the client -- no other thread is using it
    {
        std::lock_guard<std::mutex> lock(m_client_mutex);
        client_.reset();
    }

    if (vector_enabled_.exchange(false)) {
        vector_sink_.close();
    }

    std::cerr << "[MetricsLogger] CH client cleanup complete" << std::endl;
}

// Create client and tables on main thread during init() - call ONCE
void MetricsLogger::create_client_and_tables_() {
    if (m_tables_initialized.load() || !ch_.enabled || m_shutting_down.load()) return;
    
    std::lock_guard<std::mutex> lock(m_client_mutex);
    if (m_tables_initialized.load()) return;  // Double-check after lock
    
    try {
        std::cerr << "[MetricsLogger] Connecting to ClickHouse at "
                  << ch_.host << ":" << ch_.port 
                  << " (database: " << ch_.database << ")" << std::endl;
        client_ = std::make_unique<ClickHouseClient>(ch_);
        std::cerr << "[MetricsLogger] Successfully connected to ClickHouse" << std::endl;

        if (!m_shutting_down.load()) {
            ensure_tables_();
            m_tables_initialized.store(true);
            std::cerr << "[MetricsLogger] All tables initialized on main thread" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "[MetricsLogger] ERROR: Failed to connect to ClickHouse: " 
                  << e.what() << std::endl;
        ch_.enabled = false;  // Disable future attempts
        client_.reset();
        throw;
    } catch (...) {
        std::cerr << "[MetricsLogger] ERROR: Failed to connect to ClickHouse: unknown exception" << std::endl;
        ch_.enabled = false;
        client_.reset();
        throw;
    }
}

// Reconnect client (does NOT create tables - they were created in init)
// Caller must NOT hold m_client_mutex.
void MetricsLogger::ensure_client_() {
    std::lock_guard<std::mutex> lock(m_client_mutex);
    ensure_client_unlocked_();
}

// Same as ensure_client_ but caller must already hold m_client_mutex.
void MetricsLogger::ensure_client_unlocked_() {
    if (client_ || !ch_.enabled || m_shutting_down.load()) return;

    try {
        std::cerr << "[MetricsLogger] Reconnecting to ClickHouse at "
                  << ch_.host << ":" << ch_.port << std::endl;
        client_ = std::make_unique<ClickHouseClient>(ch_);
        std::cerr << "[MetricsLogger] Successfully reconnected to ClickHouse" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[MetricsLogger] ERROR: Failed to reconnect to ClickHouse: "
                  << e.what() << std::endl;
        client_.reset();
        throw;
    } catch (...) {
        std::cerr << "[MetricsLogger] ERROR: Failed to reconnect: unknown exception" << std::endl;
        client_.reset();
        throw;
    }
}
#else
// Non-ClickHouse build: stub implementations
MetricsLogger::MetricsLogger() = default;
MetricsLogger::~MetricsLogger() = default;

void MetricsLogger::wait_for_queue_drain_() {
    m_shutting_down.store(true);
    if (vector_enabled_.exchange(false)) {
        vector_sink_.close();
    }
    std::cerr << "[MetricsLogger] Shutdown complete (CH disabled)" << std::endl;
}
#endif

// --- Vector JSONL helpers (always compiled, no clickhouse-cpp dependency) ---

void MetricsLogger::add_common_fields_(JsonBuilder& jb) {
    jb.add("session_id", session_id_);
    jb.add("fuzzer_name", fuzzer_name_);
    jb.add("harness_name", harness_name_);
    jb.add("fuzz_target", fuzz_target_);
    jb.add_string_array("target_names", target_names_);
    jb.add_string_array("target_paths", target_paths_);
    jb.add("program_id", program_id_);
    jb.add("syscall_name", syscall_name_);
    jb.add("user_name", user_name_);
    jb.add("host_name", host_name_);
    jb.add("task_id", task_id_);
    jb.add("bundle_id", bundle_id_);
    jb.add("asset_id", asset_id_);
    jb.add("organization", organization_);
    jb.add("project", project_);
    jb.add("lineage_name", lineage_name_);
    jb.add("corpus_group", corpus_group_);
    jb.add("task_type", task_type_);
}

void MetricsLogger::emit_jsonl_(const std::string& table, JsonBuilder& jb) {
    jb.add("_table", table);
    vector_sink_.write(jb.finish());
}

void MetricsLogger::set_shutting_down(bool shutting_down) {
    m_shutting_down.store(shutting_down);
#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (shutting_down) {
        std::cerr << "[MetricsLogger] Shutdown flag set, no new connections will be attempted" << std::endl;
    }
#endif
}

void MetricsLogger::ensure_connection() {
#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled || m_shutting_down.load()) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_client_mutex);
    try {
        if (!client_) {
            ensure_client_unlocked_();
        }
    } catch (const std::exception& e) {
        std::cerr << "[MetricsLogger] WARNING: Connection check failed: " << e.what()
                  << ", will reconnect on next insert" << std::endl;
        client_.reset();
    } catch (...) {
        std::cerr << "[MetricsLogger] WARNING: Connection check failed: unknown exception" << std::endl;
        client_.reset();
    }
#endif
}

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
void MetricsLogger::reconnect_if_needed_() {
    if (!ch_.enabled || m_shutting_down.load()) return;

    std::lock_guard<std::mutex> lock(m_client_mutex);
    if (!client_) {
        try {
            ensure_client_unlocked_();
        } catch (...) { } // Connection failed, will be handled by individual Insert calls
    }
}

// Actual insert implementation (called from background thread).
// Holds m_client_mutex for the duration of the insert.
bool MetricsLogger::insert_with_retry_(const std::string& table_name, void* block_ptr, const std::string& operation_desc) {
    if (!ch_.enabled) return false;

    // Skip ClickHouse operations during shutdown/atexit to avoid crashes.
    // During atexit, static objects in clickhouse-cpp (like TypeAst cache) may
    // already be destroyed, causing SEGV if we try to insert.
    if (m_shutting_down.load()) {
        std::cerr << "[MetricsLogger] Skipping insert during shutdown: " << operation_desc << std::endl;
        return false;
    }

    // Cast back to Block (we know it's a Block because we control all callers)
    auto& b = *static_cast<clickhouse::Block*>(block_ptr);

    std::lock_guard<std::mutex> lock(m_client_mutex);

    // Try insert, with reconnection on connection errors
    for (int attempt = 0; attempt < 2; ++attempt) {
        try {
            if (!client_) {
                ensure_client_unlocked_();
            }

            client_->c().Insert(table_name, b);
            return true;
        } catch (const std::exception& e) {
            std::string error_msg = e.what();
            bool is_connection_error = (error_msg.find("closed") != std::string::npos) ||
                                       (error_msg.find("No such file") != std::string::npos) ||
                                       (error_msg.find("Broken pipe") != std::string::npos) ||
                                       (error_msg.find("Connection") != std::string::npos);

            if (m_shutting_down.load()) {
                std::cerr << "[MetricsLogger] Shutting down, skipping reconnection for " << operation_desc << std::endl;
                return false;
            }

            if (is_connection_error && attempt == 0) {
                std::cerr << "[MetricsLogger] Connection lost during " << operation_desc
                          << ", attempting to reconnect..." << std::endl;
                client_.reset();
            } else {
                std::cerr << "[MetricsLogger] ERROR: Failed to insert " << operation_desc << ": "
                          << error_msg << std::endl;
                return false;
            }
        } catch (...) {
            std::cerr << "[MetricsLogger] ERROR: Failed to insert " << operation_desc
                      << ": unknown exception" << std::endl;
            return false;
        }
    }

    return false;
}

// Insert wrapper -- moves the Block into a closure and enqueues it for async
// execution on the background logger thread.  This keeps ClickHouse I/O off
// the fuzzing hot-path.
void MetricsLogger::enqueue_insert_(const std::string& table_name, void* block_ptr, const std::string& operation_desc) {
    // Move the caller's Block into a shared_ptr so the lambda can own it.
    // (std::function requires copyable captures; unique_ptr would not work.)
    auto block = std::make_shared<clickhouse::Block>(
        std::move(*static_cast<clickhouse::Block*>(block_ptr)));

    enqueue_log_([this, table_name, block, operation_desc]() {
        bool success = insert_with_retry_(table_name, block.get(), operation_desc);
        if (!success) {
            std::cerr << "[MetricsLogger] ERROR: Failed to insert " << block->GetRowCount()
                      << " rows to " << table_name << std::endl;
        }
    }, operation_desc);
}

// Table schema definition structure
struct TableSchema {
    std::string name;
    std::vector<std::pair<std::string, std::string>> columns;  // (name, type) pairs
    std::string partition_by;
    std::vector<std::string> order_by;
    uint32_t index_granularity = 8192;
    std::string engine_type = "MergeTree";  // MergeTree or ReplacingMergeTree
};

// Common columns from init() parameters that should be in all tables
static std::vector<std::pair<std::string, std::string>> get_common_columns() {
    return {
        {"session_id", "String"},
        {"fuzzer_name", "String"},
        {"harness_name", "String"},
        {"fuzz_target", "String"},
        {"target_names", "Array(String)"},
        {"target_paths", "Array(String)"},
        {"program_id", "String"},
        {"syscall_name", "String"},
        {"user_name", "String"},
        {"host_name", "String"},
        {"task_id", "String"},
        {"bundle_id", "String"},
        {"asset_id", "String"},
        {"organization", "String"},
        {"project", "String"},
        {"lineage_name", "String"},
        {"corpus_group", "String"},
        {"task_type", "String"},
    };
}

// Helper: Merge common columns into a table schema, ensuring no duplicates
static void merge_common_columns(std::vector<std::pair<std::string, std::string>>& columns) {
    auto common = get_common_columns();
    std::set<std::string> existing;
    for (const auto& col : columns) {
        existing.insert(col.first);
    }
    
    // Insert common columns that don't already exist (after session_id and before event_time)
    // Find where to insert (after session_id, before event_time if present)
    size_t insert_pos = 0;
    for (size_t i = 0; i < columns.size(); ++i) {
        if (columns[i].first == "session_id") {
            insert_pos = i + 1;
            break;
        }
        if (columns[i].first == "event_time") {
            insert_pos = i;
            break;
        }
    }
    
    // Insert common columns in reverse order to maintain correct position
    for (auto it = common.rbegin(); it != common.rend(); ++it) {
        if (existing.find(it->first) == existing.end()) {
            columns.insert(columns.begin() + insert_pos, *it);
        }
    }
}

// Helper macros to reduce boilerplate for column creation, appending, and block insertion
#define APPEND_STRING_COLUMN(block, col_name, value) \
    do { \
        auto col = std::make_shared<clickhouse::ColumnString>(); \
        col->Append(value); \
        (block).AppendColumn(col_name, col); \
    } while(0)

#define APPEND_UINT32_COLUMN(block, col_name, value) \
    do { \
        auto col = std::make_shared<clickhouse::ColumnUInt32>(); \
        col->Append(value); \
        (block).AppendColumn(col_name, col); \
    } while(0)

#define APPEND_UINT64_COLUMN(block, col_name, value) \
    do { \
        auto col = std::make_shared<clickhouse::ColumnUInt64>(); \
        col->Append(value); \
        (block).AppendColumn(col_name, col); \
    } while(0)

#define APPEND_FLOAT32_COLUMN(block, col_name, value) \
    do { \
        auto col = std::make_shared<clickhouse::ColumnFloat32>(); \
        col->Append(value); \
        (block).AppendColumn(col_name, col); \
    } while(0)

#define APPEND_FLOAT64_COLUMN(block, col_name, value) \
    do { \
        auto col = std::make_shared<clickhouse::ColumnFloat64>(); \
        col->Append(value); \
        (block).AppendColumn(col_name, col); \
    } while(0)

#define APPEND_DATETIME64_COLUMN(block, col_name, value, precision) \
    do { \
        auto col = std::make_shared<clickhouse::ColumnDateTime64>(precision); \
        col->Append(value); \
        (block).AppendColumn(col_name, col); \
    } while(0)

#define APPEND_STRING_ARRAY_COLUMN(block, col_name, values) \
    do { \
        auto inner = std::make_shared<clickhouse::ColumnString>(); \
        auto offsets = std::make_shared<clickhouse::ColumnUInt64>(); \
        for (const auto& v : values) { \
            inner->Append(v); \
        } \
        /* Offset marks end of this row's array elements */ \
        offsets->Append(inner->Size()); \
        auto col = std::make_shared<clickhouse::ColumnArray>(inner, offsets); \
        (block).AppendColumn(col_name, col); \
    } while(0)

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
// Helper: Append common columns to a block (member function to access instance variables)
void MetricsLogger::append_common_columns_to_block_(void* block_ptr) {
    auto& block = *static_cast<clickhouse::Block*>(block_ptr);
    APPEND_STRING_COLUMN(block, "session_id", session_id_);
    APPEND_STRING_COLUMN(block, "fuzzer_name", fuzzer_name_);
    APPEND_STRING_COLUMN(block, "harness_name", harness_name_);
    APPEND_STRING_COLUMN(block, "fuzz_target", fuzz_target_);
    APPEND_STRING_ARRAY_COLUMN(block, "target_names", target_names_);
    APPEND_STRING_ARRAY_COLUMN(block, "target_paths", target_paths_);
    APPEND_STRING_COLUMN(block, "program_id", program_id_);
    APPEND_STRING_COLUMN(block, "syscall_name", syscall_name_);
    APPEND_STRING_COLUMN(block, "user_name", user_name_);
    APPEND_STRING_COLUMN(block, "host_name", host_name_);
    APPEND_STRING_COLUMN(block, "task_id", task_id_);
    APPEND_STRING_COLUMN(block, "bundle_id", bundle_id_);
    APPEND_STRING_COLUMN(block, "asset_id", asset_id_);
    APPEND_STRING_COLUMN(block, "organization", organization_);
    APPEND_STRING_COLUMN(block, "project", project_);
    APPEND_STRING_COLUMN(block, "lineage_name", lineage_name_);
    APPEND_STRING_COLUMN(block, "corpus_group", corpus_group_);
    APPEND_STRING_COLUMN(block, "task_type", task_type_);
}
#endif

// Declarative table schemas
static const std::vector<TableSchema> get_table_schemas() {
    std::vector<TableSchema> schemas = {
        {
            "session_events",
            {
                {"session_id", "String"},
                {"event_time", "DateTime64(3)"},
                {"event_type", "LowCardinality(String)"},
                {"status", "String"},
                {"total_executions", "UInt64"},
                {"total_crashes", "UInt64"},
                {"total_hangs", "UInt64"},
                {"cpu_hours", "Float64"},
                {"memory_peak_mb", "UInt64"},
                {"corpus_size", "UInt64"},
                {"num_coverage_lines", "UInt32"},
                {"num_coverage_branches", "UInt32"},
                {"num_coverage_functions", "UInt32"},
            },
            "toYYYYMM(event_time)",
            {"event_time", "session_id", "event_type"}
        },
        {
            "execution_events",
            {
                {"session_id", "String"},
                {"fuzzer_name", "String"},
                {"harness_name", "String"},
                {"fuzz_target", "String"},
                {"target_names", "Array(String)"},
                {"target_paths", "Array(String)"},
                {"program_id", "String"},
                {"syscall_name", "String"},
                {"user_name", "String"},
                {"host_name", "String"},
                {"task_id", "String"},
                {"bundle_id", "String"},
                {"asset_id", "String"},
                {"organization", "String"},
                {"project", "String"},
                {"lineage_name", "String"},
                {"corpus_group", "String"},
                {"task_type", "String"},
                {"event_time", "DateTime64(3)"},
                {"fuzzer_state", "LowCardinality(String)"},
                {"dry_run_tested", "UInt64"},
                {"dry_run_total", "UInt64"},
                {"total_executions", "UInt64"},
                {"total_crashes", "UInt64"},
                {"total_hangs", "UInt64"},
                {"cpu_usage_pct", "Float32"},
                {"memory_usage_mb", "UInt64"},
                {"num_coverage_lines", "UInt32"},
                {"num_coverage_branches", "UInt32"},
                {"num_coverage_functions", "UInt32"},
                {"coverage_cmp", "UInt64"},
                {"coverage_edge_bucket", "UInt64"},
                {"corpus_size", "UInt64"},
                {"corpus_diversity_score", "Float32"},
                {"total_mutations_executed", "UInt64"},
                {"total_mutations_successful", "UInt64"},
                {"mutation_success_rate", "Float32"},
                {"new_features_discovered", "UInt64"},
                {"execs_delta", "UInt64"},
                {"proto_parse_calls", "UInt64"},
                {"proto_parse_successes", "UInt64"},
                {"custom_mutator_calls", "UInt64"},
                {"custom_mutator_successes", "UInt64"},
                {"sched_total", "UInt64"},
                {"repeat_pct", "Float32"},
                {"high_priority_pct", "Float32"},
                {"low_priority_pct", "Float32"},
                {"phase2_pct", "Float32"},
                {"avg_energy", "UInt64"},
                {"avg_iters", "Float32"},
                {"max_iters", "UInt64"},
                {"energy_min", "UInt64"},
                {"energy_max", "UInt64"},
                {"novelty_decay_cnt", "UInt64"},
                {"fresh_boost_cnt", "UInt64"},
                {"stale_penalty_cnt", "UInt64"},
                {"diminishing_cnt", "UInt64"},
                {"depth_penalty_cnt", "UInt64"},
                {"corpus_count", "UInt64"},
                {"global_avg_energy", "UInt64"},
                {"exec_avg_us", "UInt64"},
                {"exec_max_us", "UInt64"},
                {"slow_exec_cnt", "UInt64"},
                {"mut_hit_rate_pct", "Float32"},
                {"plateau_secs", "UInt64"},
                {"queue_wraps", "UInt64"},
                {"max_depth", "UInt32"},
                {"unique_crashes", "UInt64"},
                {"timeouts", "UInt64"},
                {"fertile_boosts", "UInt64"},
                {"saturated_lineages", "UInt64"},
                {"explore_selects", "UInt64"},
                {"secs_since_crash", "UInt64"},
                {"stagnation_secs", "UInt64"},
                {"corpus_growth", "UInt64"},
                {"inputs_truncated_too_large", "UInt64"},
                {"proto_round_cnt", "UInt64"},
                {"proto_scan_ok_cnt", "UInt64"},
                {"total_round_cnt", "UInt64"},
                {"lpm_mutate_cnt", "UInt64"},
                {"lpm_crossover_cnt", "UInt64"},
                {"lpm_parse_success_cnt", "UInt64"},
                {"lpm_parse_fail_cnt", "UInt64"},
                {"encode_overflow_cnt", "UInt64"},
                {"no_candidates_cnt", "UInt64"},
                {"elf_fixup_ok_cnt", "UInt64"},
                {"exec_fail_cnt", "UInt64"},
                {"verify_cnt", "UInt64"},
                {"harness_reject_cnt", "UInt64"},
            },
            "toYYYYMM(event_time)",
            {"event_time", "session_id"}
        },
        {
            "coverage_events",
            {
                {"session_id", "String"},
                {"event_time", "DateTime64(3)"},
                {"component", "String"},
                {"file_path", "String"},
                {"function_name", "String"},
                {"start_line", "UInt32"},
                {"end_line", "UInt32"},
                {"coverage_type", "LowCardinality(String)"},
                {"hits", "UInt64"},
                {"line_hits", "Array(UInt32)"},
                {"line_numbers", "Array(UInt32)"},
            },
            "toYYYYMM(event_time)",
            {"event_time", "session_id", "component", "file_path", "function_name", "start_line"}
        },
        {
            "bug_events",
            {
                {"bug_id", "String"},
                {"session_id", "String"},
                {"event_time", "DateTime64(3)"},
                {"event_type", "LowCardinality(String)"},
                {"component", "String"},
                {"file_path", "String"},
                {"function_name", "String"},
                {"line_number", "UInt32"},
                {"bug_type", "String"},
                {"severity", "String"},
                {"status", "String"},
                {"reproduction_time_ms", "UInt32"},
                {"input_size_bytes", "UInt32"},
                {"stack_trace", "String"},
                {"fix_commit", "String"},
            },
            "toYYYYMM(event_time)",
            {"event_time", "session_id", "bug_id", "event_type"}
        },
        {
            "mismatch_events",
            {
                {"session_id", "String"},
                {"event_time", "DateTime64(3)"},
                {"category", "String"},
                {"expected", "String"},
                {"actual", "String"},
                {"details", "String"},
            },
            "toYYYYMM(event_time)",
            {"event_time", "session_id", "category"}
        },
        {
            "execution_coverage_events",
            {
                {"session_id", "String"},
                {"event_time", "DateTime64(3)"},
                {"execution_id", "UInt64"},
                {"component", "String"},
                {"file_path", "String"},
                {"function_name", "String"},
                {"start_line", "UInt32"},
                {"end_line", "UInt32"},
                {"coverage_type", "LowCardinality(String)"},
            },
            "toYYYYMM(event_time)",
            {"event_time", "session_id", "execution_id", "component", "file_path", "function_name", "start_line"}
        },
        // Event-sourced coverage: only log WHEN each guard was first hit
        {
            "coverage_guard_first_hits",
            {
                {"session_id", "String"},
                {"first_hit_time", "DateTime64(3)"},
                {"guard_id", "UInt32"},
                {"file_path", "String"},
                {"function_name", "String"},
                {"line_number", "UInt32"},
                {"module_name", "String"},
                {"coverage_type", "LowCardinality(String)"},
            },
            "toYYYYMM(first_hit_time)",
            {"lineage_name", "session_id", "module_name", "guard_id"},
            8192,
            "ReplacingMergeTree"  // Deduplicate on re-inserts
        }
    };
    
    // Merge common columns into all schemas
    for (auto& schema : schemas) {
        merge_common_columns(schema.columns);
    }
    
    return schemas;
}

// Helper: Generate CREATE TABLE DDL from schema
static std::string generate_create_table_ddl(const TableSchema& schema) {
    std::ostringstream ddl;
    ddl << "CREATE TABLE IF NOT EXISTS " << schema.name << " (\n";
    
    for (size_t i = 0; i < schema.columns.size(); ++i) {
        const auto& col = schema.columns[i];
        ddl << "    " << col.first << " " << col.second;
        if (i < schema.columns.size() - 1) {
            ddl << ",";
        }
        ddl << "\n";
    }
    
    ddl << ") ENGINE = " << schema.engine_type << "()\n";
    ddl << "PARTITION BY " << schema.partition_by << "\n";
    ddl << "ORDER BY (";
    for (size_t i = 0; i < schema.order_by.size(); ++i) {
        ddl << schema.order_by[i];
        if (i < schema.order_by.size() - 1) {
            ddl << ", ";
        }
    }
    ddl << ")\n";
    ddl << "SETTINGS index_granularity = " << schema.index_granularity;
    
    return ddl.str();
}

// Helper: Get existing column names from ClickHouse table
static std::set<std::string> get_existing_columns(clickhouse::Client& client, const std::string& database, const std::string& table_name) {
    std::set<std::string> columns;

    try {
        std::string query = "SELECT name FROM system.columns WHERE database = '" + database
                          + "' AND table = '" + table_name + "'";

        client.Select(query, [&columns](const clickhouse::Block& block) {
            if (block.GetColumnCount() > 0) {
                auto col_ptr = block[0];
                auto col = col_ptr->As<clickhouse::ColumnString>();
                if (col) {
                    for (size_t i = 0; i < col->Size(); ++i) {
                        std::string col_name{ col->At(i) };
                        columns.insert(col_name);
                    }
                }
            }
        });
    } catch (const std::exception& e) {
        std::cerr << "[MetricsLogger] WARNING: Failed to query existing columns for table '"
                  << table_name << "': " << e.what() << std::endl;
    }

    return columns;
}

void MetricsLogger::ensure_tables_() {
    if (!client_ || !ch_.enabled) return;

    // Get declarative table schemas
    const auto schemas = get_table_schemas();

    std::cerr << "[MetricsLogger] Ensuring ClickHouse tables exist in database '" 
              << ch_.database << "'..." << std::endl;

    size_t success_count = 0;
    size_t fail_count = 0;
    
    for (const auto& schema : schemas) {
        std::cerr << "[MetricsLogger] Creating/verifying table '" << schema.name << "'..." << std::endl;
        
        try {
            // Step 1: Generate and execute CREATE TABLE IF NOT EXISTS
            std::string ddl = generate_create_table_ddl(schema);
            client_->c().Execute(ddl);
            
            // Step 2: Check existing columns and compare with desired schema
            std::set<std::string> existing_cols = get_existing_columns(client_->c(), ch_.database, schema.name);

            if (!existing_cols.empty() && !schema.columns.empty()) {
                // Find missing columns (columns in desired but not in existing)
                std::vector<std::pair<std::string, std::string>> missing_cols;
                for (const auto& desired : schema.columns) {
                    if (existing_cols.find(desired.first) == existing_cols.end()) {
                        missing_cols.push_back(desired);
                    }
                }

                // Add missing columns if any
                if (!missing_cols.empty()) {
                    std::cerr << "[MetricsLogger] Table '" << schema.name
                              << "' is missing " << missing_cols.size() << " column(s), adding them..." << std::endl;

                    for (const auto& col : missing_cols) {
                        try {
                            std::string alter_sql = "ALTER TABLE " + schema.name
                                                  + " ADD COLUMN IF NOT EXISTS " + col.first + " " + col.second;

                            std::cerr << "[MetricsLogger] Adding column '" << col.first
                                      << "' with type '" << col.second << "'..." << std::endl;
                            client_->c().Execute(alter_sql);
                            std::cerr << "[MetricsLogger] Successfully added column '" << col.first << "'" << std::endl;
                        } catch (const std::exception& e) {
                            std::cerr << "[MetricsLogger] WARNING: Failed to add column '" << col.first
                                      << "' to table '" << schema.name << "': " << e.what() << std::endl;
                        }
                    }
                } else {
                    std::cerr << "[MetricsLogger] Table '" << schema.name
                              << "' schema is up-to-date (existing: " << existing_cols.size()
                              << " columns, desired: " << schema.columns.size() << " columns)" << std::endl;

                    // Log if existing table has more columns than desired (which is OK)
                    if (existing_cols.size() > schema.columns.size()) {
                        std::cerr << "[MetricsLogger] Note: Existing table has "
                                  << (existing_cols.size() - schema.columns.size())
                                  << " additional column(s), which is acceptable (superset)" << std::endl;
                    }
                }
            }

            // Promote columns that were originally UInt32 to UInt64
            if (schema.name == "execution_events" || schema.name == "session_events") {
                const char* promote_cols[] = {"total_executions", "total_crashes", "total_hangs"};
                for (const auto& col_name : promote_cols) {
                    if (existing_cols.count(col_name)) {
                        try {
                            std::string sql = "ALTER TABLE " + schema.name
                                            + " MODIFY COLUMN " + col_name + " UInt64";
                            client_->c().Execute(sql);
                        } catch (const std::exception&) {
                            // Already UInt64 or unsupported — harmless
                        }
                    }
                }
            }
            
            std::cerr << "[MetricsLogger] Successfully created/verified table '" 
                      << schema.name << "'" << std::endl;
            success_count++;
        } catch (const std::exception& e) {
            std::cerr << "[MetricsLogger] WARNING: Failed to create table '" << schema.name 
                      << "': " << e.what() << std::endl;
            fail_count++;
            // Continue with other tables
        } catch (...) {
            std::cerr << "[MetricsLogger] WARNING: Failed to create table '" << schema.name 
                      << "': unknown exception" << std::endl;
            fail_count++;
        }
    }

    std::cerr << "[MetricsLogger] Finished ensuring tables: " << success_count
              << " succeeded, " << fail_count << " failed" << std::endl;
}

void MetricsLogger::ensure_kind_columns_(const char* const* kind_names, uint32_t kind_num) {
    if (!ch_.enabled || !m_tables_initialized.load()) return;

    std::lock_guard<std::mutex> lock(m_client_mutex);
    if (!client_) {
        try { ensure_client_unlocked_(); } catch (...) {}
        if (!client_) return;
    }

    for (uint32_t k = 0; k < kind_num; k++) {
        std::string col = sanitize_kind_col(kind_names[k]);

        if (ensured_kind_columns_.count(col)) continue;

        try {
            std::string sql = "ALTER TABLE execution_events ADD COLUMN IF NOT EXISTS "
                            + col + " UInt64 DEFAULT 0";
            client_->c().Execute(sql);
            ensured_kind_columns_.insert(col);
        } catch (const std::exception& e) {
            std::cerr << "[MetricsLogger] WARNING: Failed to add kind column '"
                      << col << "': " << e.what() << std::endl;
        }
    }
}
#endif


void MetricsLogger::init(
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
    const std::string& task_type)
{
#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    // Harness-side ClickHouse logging is ONLY enabled when SOLFUZZ_HARNESS_CH_ENABLE=1.
    // This is separate from SOLFUZZ_CH_ENABLE which controls the parent honggfuzz process.
    // When fuzzing with honggfuzz, the parent process handles all CH logging via the
    // metrics bridge, and sets SOLFUZZ_PARENT_METRICS=1 to tell the harness to skip.
    // For standalone harness runs (e.g., validation, testing), CH logging is disabled
    // by default to avoid crashes during atexit from clickhouse-cpp static destruction.
    ch_.enabled  = getenv_or("SOLFUZZ_HARNESS_CH_ENABLE", "0") == "1";
    ch_.host     = getenv_or("SOLFUZZ_CH_HOST", "127.0.0.1");
    ch_.port     = static_cast<uint16_t>(std::atoi(getenv_or("SOLFUZZ_CH_PORT", "9000").c_str()));
    ch_.secure   = getenv_or("SOLFUZZ_CH_SECURE", "0") == "1";
    ch_.database = getenv_or("SOLFUZZ_CH_DB", "default");
    ch_.user     = getenv_or("SOLFUZZ_CH_USER", "");
    ch_.password = getenv_or("SOLFUZZ_CH_PASSWORD", "");
#endif

    session_id_ = session_id;
    user_name_ = user_name;
    host_name_ = host_name;
    fuzzer_name_ = fuzzer_name;
    harness_name_ = harness_name;
    fuzz_target_ = fuzz_target;
    target_names_ = target_names;
    target_paths_ = target_paths;
    program_id_ = program_id;
    syscall_name_ = syscall_name;
    task_id_ = task_id;
    bundle_id_ = bundle_id;
    asset_id_ = asset_id;
    organization_ = organization;
    project_ = project;
    lineage_name_ = lineage_name;
    corpus_group_ = corpus_group;
    task_type_ = task_type;

    // Vector JSONL output -- works with or without SOLFUZZ_CLICKHOUSE_ENABLED.
    if (getenv_or("SOLFUZZ_VECTOR_ENABLE", "0") == "1") {
        std::string sink_path = getenv_or("SOLFUZZ_VECTOR_SINK_PATH", "");
        if (sink_path.empty()) {
            std::string sink_dir = getenv_or("SOLFUZZ_VECTOR_SINK_DIR", "/data/tmp/vector");
            sink_path = sink_dir + "/solfuzz_metrics_" + session_id + ".jsonl";
        }
        if (vector_sink_.open(sink_path)) {
            vector_enabled_.store(true);
            std::cerr << "[MetricsLogger] Vector JSONL output enabled: " << sink_path << std::endl;
        } else {
            std::cerr << "[MetricsLogger] WARNING: Failed to open Vector sink, falling back" << std::endl;
        }
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (ch_.enabled) {
        try {
            // Create client and tables ONCE on main thread before starting background threads
            create_client_and_tables_();
            
            // Start background logger thread for async inserts
            if (!m_logger_running.load() && m_tables_initialized.load()) {
                m_logger_running.store(true);
                m_logger_thread = std::thread(&MetricsLogger::logger_thread_func_, this);
                std::cerr << "[MetricsLogger] Started background logger thread" << std::endl;
            }
        } catch (...) {
            // Already logged in create_client_and_tables_()
            ch_.enabled = false;
        }
    }
#endif

    std::cerr << "[MetricsLogger] Initialized for session: " << session_id 
              << ", target: " << fuzz_target;
#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    std::cerr << (ch_.enabled ? " [CH enabled]" : " [CH disabled]");
#endif
    std::cerr << (vector_enabled_.load() ? " [Vector enabled]" : "");
    std::cerr << std::endl;
}

void MetricsLogger::log_session_start()
{
    std::cerr << "[MetricsLogger] Session started: " << session_id_ 
              << ", fuzzer: " << fuzzer_name_ 
              << ", harness: " << harness_name_ 
              << ", target: " << fuzz_target_ << std::endl;
    std::cerr.flush();
    
    // Also write to debug log file if set
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[MetricsLogger] Session started: " << session_id_ 
            << ", fuzzer: " << fuzzer_name_ 
            << ", harness: " << harness_name_ 
            << ", target: " << fuzz_target_ << std::endl;
        dbg.flush();  // Ensure message is written to disk immediately
    }
    
    log_session_event("start", "", 0, 0, 0, 0.0, 0, 0);
}

void MetricsLogger::log_session_end(
    const std::string& status,
    uint64_t total_executions,
    uint64_t total_crashes,
    uint64_t total_hangs,
    float cpu_hours,
    uint64_t memory_peak_mb,
    uint64_t corpus_size)
{
    std::cerr << "[MetricsLogger] log_session_end() called (pid=" << getpid() << ")" << std::endl;
    std::cerr.flush();
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[MetricsLogger] log_session_end() called (pid=" << getpid() << ")" << std::endl;
        dbg.flush();
    }
    
    std::cerr << "[MetricsLogger] Session ended: " << session_id_ 
              << ", status: " << status 
              << ", executions: " << total_executions 
              << ", crashes: " << total_crashes 
              << ", hangs: " << total_hangs 
              << ", cpu_hours: " << std::fixed << std::setprecision(2) << cpu_hours << std::endl;
    std::cerr.flush();
    
    // Also write to debug log file if set
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[MetricsLogger] Session ended: " << session_id_ 
            << ", status: " << status 
            << ", executions: " << total_executions 
            << ", crashes: " << total_crashes 
            << ", hangs: " << total_hangs 
            << ", cpu_hours: " << std::fixed << std::setprecision(2) << cpu_hours << std::endl;
        dbg.flush();  // Ensure message is written to disk immediately
        std::cerr << "[MetricsLogger] Session end message written to debug log file" << std::endl;
        std::cerr.flush();
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    // Ensure connection is alive before logging session end (critical operation)
    if (ch_.enabled) {
        ensure_connection();
    }
#endif

    log_session_event("end", status, total_executions, total_crashes, total_hangs,
                      cpu_hours, memory_peak_mb, corpus_size);
}

void MetricsLogger::log_session_event(
    const std::string& event_type,
    const std::string& status,
    uint64_t total_executions,
    uint64_t total_crashes,
    uint64_t total_hangs,
    float cpu_hours,
    uint64_t memory_peak_mb,
    uint64_t corpus_size)
{
    uint32_t num_coverage_lines = 0;
    uint32_t num_coverage_branches = 0;
    uint32_t num_coverage_functions = 0;
    if (vector_enabled_.load()) {
        JsonBuilder jb;
        add_common_fields_(jb);
        jb.add_timestamp("event_time", now_epoch_ms());
        jb.add("event_type", event_type);
        jb.add("status", status);
        jb.add("total_executions", total_executions);
        jb.add("total_crashes", total_crashes);
        jb.add("total_hangs", total_hangs);
        jb.add("cpu_hours", static_cast<double>(cpu_hours));
        jb.add("memory_peak_mb", memory_peak_mb);
        jb.add("corpus_size", corpus_size);
        jb.add("num_coverage_lines", num_coverage_lines);
        jb.add("num_coverage_branches", num_coverage_branches);
        jb.add("num_coverage_functions", num_coverage_functions);
        emit_jsonl_("session_events", jb);
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled || !m_tables_initialized.load()) return;

    clickhouse::Block b;

    // Append common columns first
    append_common_columns_to_block_(&b);

    // Table-specific columns
    APPEND_DATETIME64_COLUMN(b, "event_time", now_epoch_ms_(), 3);
    APPEND_STRING_COLUMN(b, "event_type", event_type);
    APPEND_STRING_COLUMN(b, "status", status);
    APPEND_UINT64_COLUMN(b, "total_executions", total_executions);
    APPEND_UINT64_COLUMN(b, "total_crashes", total_crashes);
    APPEND_UINT64_COLUMN(b, "total_hangs", total_hangs);
    APPEND_FLOAT64_COLUMN(b, "cpu_hours", cpu_hours);
    APPEND_UINT64_COLUMN(b, "memory_peak_mb", memory_peak_mb);
    APPEND_UINT64_COLUMN(b, "corpus_size", corpus_size);
    APPEND_UINT32_COLUMN(b, "num_coverage_lines", num_coverage_lines);
    APPEND_UINT32_COLUMN(b, "num_coverage_branches", num_coverage_branches);
    APPEND_UINT32_COLUMN(b, "num_coverage_functions", num_coverage_functions);

    std::string event_desc = "session " + event_type + " event";

    enqueue_insert_("session_events", &b, event_desc);
#endif
}

void MetricsLogger::log_fuzzer_stats(
    uint64_t total_executions,
    uint64_t coverage_pcs,
    uint64_t coverage_edges,
    uint64_t coverage_cmp,
    uint64_t coverage_edge_bucket,
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
    uint64_t novelty_decay,
    uint64_t fresh_boost,
    uint64_t stale_penalty,
    uint64_t diminishing,
    uint64_t depth_penalty,
    uint64_t corpus_count,
    uint64_t global_avg_energy,
    uint64_t exec_avg_us,
    uint64_t exec_max_us,
    uint64_t slow_execs,
    float mut_hit_rate_pct,
    uint64_t plateau_secs,
    uint64_t queue_wraps,
    uint32_t max_depth,
    uint64_t unique_crashes,
    uint64_t total_crashes,
    uint64_t timeouts,
    uint64_t fertile_boosts,
    uint64_t saturated,
    uint64_t explore_selects,
    uint64_t secs_since_crash,
    uint64_t stagnation_secs,
    uint64_t corpus_growth,
    const std::string& fuzzer_state,
    uint64_t dry_run_tested,
    uint64_t dry_run_total,
    uint64_t inputs_truncated_too_large,
    const hfuzz_mutation_counters_t* mutation)
{
    static const hfuzz_mutation_counters_t zeros = {};
    const auto* m = mutation ? mutation : &zeros;

    uint64_t prev = prev_total_executions_.exchange(total_executions);
    uint64_t delta = (total_executions >= prev) ? total_executions - prev : 0;

    if (vector_enabled_.load()) {
        static const bool s_exec_events_enabled = [] {
            const char* v = std::getenv("SOLFUZZ_EXECUTION_EVENTS_ENABLE");
            return v && std::string(v) == "1";
        }();
        if (s_exec_events_enabled) {
            JsonBuilder jb;
            add_common_fields_(jb);
            jb.add_timestamp("event_time", now_epoch_ms());
            jb.add("fuzzer_state", fuzzer_state);
            jb.add("dry_run_tested", dry_run_tested);
            jb.add("dry_run_total", dry_run_total);
            jb.add("total_executions", total_executions);
            jb.add("total_crashes", total_crashes);
            jb.add("total_hangs", static_cast<uint64_t>(0));
            jb.add("cpu_usage_pct", 0.0f);
            jb.add("memory_usage_mb", static_cast<uint64_t>(0));
            jb.add("num_coverage_lines", static_cast<uint32_t>(coverage_pcs));
            jb.add("num_coverage_branches", static_cast<uint32_t>(coverage_edges));
            jb.add("num_coverage_functions", static_cast<uint32_t>(0));
            jb.add("coverage_cmp", coverage_cmp);
            jb.add("coverage_edge_bucket", coverage_edge_bucket);
            jb.add("corpus_size", corpus_count);
            jb.add("corpus_diversity_score", 0.0f);
            jb.add("total_mutations_executed", sched_total);
            jb.add("total_mutations_successful", static_cast<uint64_t>(0));
            jb.add("mutation_success_rate", mut_hit_rate_pct / 100.0f);
            jb.add("new_features_discovered", corpus_growth);
            jb.add("proto_parse_calls", static_cast<uint64_t>(0));
            jb.add("proto_parse_successes", static_cast<uint64_t>(0));
            jb.add("custom_mutator_calls", static_cast<uint64_t>(0));
            jb.add("custom_mutator_successes", static_cast<uint64_t>(0));
            jb.add("sched_total", sched_total);
            jb.add("repeat_pct", repeat_pct);
            jb.add("high_priority_pct", high_pct);
            jb.add("low_priority_pct", low_pct);
            jb.add("phase2_pct", phase2_pct);
            jb.add("avg_energy", avg_energy);
            jb.add("avg_iters", avg_iters);
            jb.add("max_iters", max_iters);
            jb.add("energy_min", energy_min);
            jb.add("energy_max", energy_max);
            jb.add("novelty_decay_cnt", novelty_decay);
            jb.add("fresh_boost_cnt", fresh_boost);
            jb.add("stale_penalty_cnt", stale_penalty);
            jb.add("diminishing_cnt", diminishing);
            jb.add("depth_penalty_cnt", depth_penalty);
            jb.add("corpus_count", corpus_count);
            jb.add("global_avg_energy", global_avg_energy);
            jb.add("exec_avg_us", exec_avg_us);
            jb.add("exec_max_us", exec_max_us);
            jb.add("slow_exec_cnt", slow_execs);
            jb.add("mut_hit_rate_pct", mut_hit_rate_pct);
            jb.add("plateau_secs", plateau_secs);
            jb.add("queue_wraps", queue_wraps);
            jb.add("max_depth", max_depth);
            jb.add("unique_crashes", unique_crashes);
            jb.add("timeouts", timeouts);
            jb.add("fertile_boosts", fertile_boosts);
            jb.add("saturated_lineages", saturated);
            jb.add("explore_selects", explore_selects);
            jb.add("secs_since_crash", secs_since_crash);
            jb.add("stagnation_secs", stagnation_secs);
            jb.add("corpus_growth", corpus_growth);
            jb.add("inputs_truncated_too_large", inputs_truncated_too_large);
            jb.add("execs_delta", delta);
            jb.add("proto_round_cnt", m->proto_round_cnt);
            jb.add("proto_scan_ok_cnt", m->proto_scan_ok_cnt);
            jb.add("total_round_cnt", m->total_round_cnt);
            jb.add("lpm_mutate_cnt", m->kutator_mutate_cnt);
            jb.add("lpm_crossover_cnt", m->kutator_crossover_cnt);
            jb.add("lpm_parse_success_cnt", m->kutator_parse_success_cnt);
            jb.add("lpm_parse_fail_cnt", m->kutator_parse_fail_cnt);
            jb.add("encode_overflow_cnt", m->encode_overflow_cnt);
            jb.add("no_candidates_cnt", m->no_candidates_cnt);
            jb.add("elf_fixup_ok_cnt", m->elf_fixup_ok_cnt);
            jb.add("exec_fail_cnt", m->exec_fail_cnt);
            jb.add("verify_cnt", m->verify_cnt);
            jb.add("harness_reject_cnt", m->harness_reject_cnt);
            emit_jsonl_("execution_events", jb);
        }
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled || !m_tables_initialized.load()) return;

    clickhouse::Block b;

    // Append common columns first
    append_common_columns_to_block_(&b);

    // Table-specific columns - using execution_events table for fuzzer stats
    APPEND_DATETIME64_COLUMN(b, "event_time", now_epoch_ms_(), 3);
    APPEND_UINT64_COLUMN(b, "total_executions", total_executions);
    APPEND_UINT64_COLUMN(b, "total_crashes", total_crashes);
    APPEND_UINT64_COLUMN(b, "total_hangs", 0);
    APPEND_FLOAT32_COLUMN(b, "cpu_usage_pct", 0.0f);
    APPEND_UINT64_COLUMN(b, "memory_usage_mb", 0);
    APPEND_UINT32_COLUMN(b, "num_coverage_lines", static_cast<uint32_t>(coverage_pcs));
    APPEND_UINT32_COLUMN(b, "num_coverage_branches", static_cast<uint32_t>(coverage_edges));
    APPEND_UINT32_COLUMN(b, "num_coverage_functions", 0);
    APPEND_UINT64_COLUMN(b, "coverage_cmp", coverage_cmp);
    APPEND_UINT64_COLUMN(b, "coverage_edge_bucket", coverage_edge_bucket);
    APPEND_UINT64_COLUMN(b, "corpus_size", corpus_count);
    APPEND_FLOAT32_COLUMN(b, "corpus_diversity_score", 0.0f);
    APPEND_UINT64_COLUMN(b, "total_mutations_executed", sched_total);
    APPEND_UINT64_COLUMN(b, "total_mutations_successful", 0);
    APPEND_FLOAT32_COLUMN(b, "mutation_success_rate", mut_hit_rate_pct / 100.0f);
    APPEND_UINT64_COLUMN(b, "new_features_discovered", corpus_growth);
    APPEND_UINT64_COLUMN(b, "execs_delta", delta);

    // SCHED-STATS columns
    APPEND_UINT64_COLUMN(b, "sched_total", sched_total);
    APPEND_FLOAT32_COLUMN(b, "repeat_pct", repeat_pct);
    APPEND_FLOAT32_COLUMN(b, "high_priority_pct", high_pct);
    APPEND_FLOAT32_COLUMN(b, "low_priority_pct", low_pct);
    APPEND_FLOAT32_COLUMN(b, "phase2_pct", phase2_pct);
    APPEND_UINT64_COLUMN(b, "avg_energy", avg_energy);
    APPEND_FLOAT32_COLUMN(b, "avg_iters", avg_iters);
    APPEND_UINT64_COLUMN(b, "max_iters", max_iters);
    APPEND_UINT64_COLUMN(b, "energy_min", energy_min);
    APPEND_UINT64_COLUMN(b, "energy_max", energy_max);

    // DECAY-STATS columns
    APPEND_UINT64_COLUMN(b, "novelty_decay_cnt", novelty_decay);
    APPEND_UINT64_COLUMN(b, "fresh_boost_cnt", fresh_boost);
    APPEND_UINT64_COLUMN(b, "stale_penalty_cnt", stale_penalty);
    APPEND_UINT64_COLUMN(b, "diminishing_cnt", diminishing);
    APPEND_UINT64_COLUMN(b, "depth_penalty_cnt", depth_penalty);
    APPEND_UINT64_COLUMN(b, "corpus_count", corpus_count);
    APPEND_UINT64_COLUMN(b, "global_avg_energy", global_avg_energy);

    // HEALTH-STATS columns
    APPEND_UINT64_COLUMN(b, "exec_avg_us", exec_avg_us);
    APPEND_UINT64_COLUMN(b, "exec_max_us", exec_max_us);
    APPEND_UINT64_COLUMN(b, "slow_exec_cnt", slow_execs);
    APPEND_FLOAT32_COLUMN(b, "mut_hit_rate_pct", mut_hit_rate_pct);
    APPEND_UINT64_COLUMN(b, "plateau_secs", plateau_secs);
    APPEND_UINT64_COLUMN(b, "queue_wraps", queue_wraps);
    APPEND_UINT32_COLUMN(b, "max_depth", max_depth);

    // DIFF-FUZZ-STATS columns
    APPEND_UINT64_COLUMN(b, "unique_crashes", unique_crashes);
    APPEND_UINT64_COLUMN(b, "timeouts", timeouts);
    APPEND_UINT64_COLUMN(b, "fertile_boosts", fertile_boosts);
    APPEND_UINT64_COLUMN(b, "saturated_lineages", saturated);
    APPEND_UINT64_COLUMN(b, "explore_selects", explore_selects);
    APPEND_UINT64_COLUMN(b, "secs_since_crash", secs_since_crash);
    APPEND_UINT64_COLUMN(b, "stagnation_secs", stagnation_secs);
    APPEND_UINT64_COLUMN(b, "corpus_growth", corpus_growth);
    APPEND_STRING_COLUMN(b, "fuzzer_state", fuzzer_state);
    APPEND_UINT64_COLUMN(b, "dry_run_tested", dry_run_tested);
    APPEND_UINT64_COLUMN(b, "dry_run_total", dry_run_total);
    APPEND_UINT64_COLUMN(b, "inputs_truncated_too_large", inputs_truncated_too_large);

    // Mutation-health columns from shared memory
    APPEND_UINT64_COLUMN(b, "proto_parse_calls", m->proto_parse_calls);
    APPEND_UINT64_COLUMN(b, "proto_parse_successes", m->proto_parse_successes);
    APPEND_UINT64_COLUMN(b, "custom_mutator_calls", m->custom_mutator_calls);
    APPEND_UINT64_COLUMN(b, "custom_mutator_successes", m->custom_mutator_successes);
    APPEND_UINT64_COLUMN(b, "proto_round_cnt", m->proto_round_cnt);
    APPEND_UINT64_COLUMN(b, "proto_scan_ok_cnt", m->proto_scan_ok_cnt);
    APPEND_UINT64_COLUMN(b, "total_round_cnt", m->total_round_cnt);
    APPEND_UINT64_COLUMN(b, "lpm_mutate_cnt", m->kutator_mutate_cnt);
    APPEND_UINT64_COLUMN(b, "lpm_crossover_cnt", m->kutator_crossover_cnt);
    APPEND_UINT64_COLUMN(b, "lpm_parse_success_cnt", m->kutator_parse_success_cnt);
    APPEND_UINT64_COLUMN(b, "lpm_parse_fail_cnt", m->kutator_parse_fail_cnt);
    APPEND_UINT64_COLUMN(b, "encode_overflow_cnt", m->encode_overflow_cnt);
    APPEND_UINT64_COLUMN(b, "no_candidates_cnt", m->no_candidates_cnt);
    APPEND_UINT64_COLUMN(b, "elf_fixup_ok_cnt", m->elf_fixup_ok_cnt);
    APPEND_UINT64_COLUMN(b, "exec_fail_cnt", m->exec_fail_cnt);
    APPEND_UINT64_COLUMN(b, "verify_cnt", m->verify_cnt);
    APPEND_UINT64_COLUMN(b, "harness_reject_cnt", m->harness_reject_cnt);

    enqueue_insert_("execution_events", &b, "fuzzer_stats");
#else
    (void)total_executions; (void)coverage_pcs; (void)coverage_edges; (void)coverage_cmp; (void)coverage_edge_bucket;
    (void)sched_total; (void)repeat_pct; (void)high_pct; (void)low_pct; (void)phase2_pct;
    (void)avg_energy; (void)avg_iters; (void)max_iters; (void)energy_min; (void)energy_max;
    (void)novelty_decay; (void)fresh_boost; (void)stale_penalty; (void)diminishing; (void)depth_penalty;
    (void)corpus_count; (void)global_avg_energy; (void)exec_avg_us; (void)exec_max_us;
    (void)slow_execs; (void)mut_hit_rate_pct; (void)plateau_secs; (void)queue_wraps; (void)max_depth;
    (void)unique_crashes; (void)total_crashes; (void)timeouts; (void)fertile_boosts;
    (void)saturated; (void)explore_selects; (void)secs_since_crash; (void)stagnation_secs; (void)corpus_growth;
    (void)fuzzer_state; (void)dry_run_tested; (void)dry_run_total; (void)inputs_truncated_too_large;
#endif
}

void MetricsLogger::log_execution_metrics(
    /* const std::string& session_id, */
    uint64_t total_executions,
    uint64_t total_crashes,
    uint64_t total_hangs,
    float cpu_usage,
    uint64_t memory_usage_mb,
    uint64_t corpus_size,
    float corpus_diversity_score,
    uint64_t total_mutations_executed,
    uint64_t total_mutations_successful,
    float mutation_success_rate,
    uint64_t new_features_discovered)
{
    uint32_t coverage_lines = 0;
    uint32_t coverage_branches = 0;
    uint32_t coverage_functions = 0;
    std::cerr << "[MetricsLogger] Execution metrics - exec: " << total_executions
              << ", crashes: " << total_crashes 
              << ", hangs: " << total_hangs 
              << ", cpu: " << cpu_usage << "%"
              << ", memory: " << memory_usage_mb << " MB"
              << ", mutations: " << total_mutations_executed << " exec ("
              << std::fixed << std::setprecision(1) << (mutation_success_rate * 100.0f) << "% success)"
              << ", new_features: " << new_features_discovered << std::endl;

    if (vector_enabled_.load()) {
        static const bool s_exec_events_enabled = [] {
            const char* v = std::getenv("SOLFUZZ_EXECUTION_EVENTS_ENABLE");
            return v && std::string(v) == "1";
        }();
        if (s_exec_events_enabled) {
            JsonBuilder jb;
            add_common_fields_(jb);
            jb.add_timestamp("event_time", now_epoch_ms());
            jb.add("total_executions", total_executions);
            jb.add("total_crashes", total_crashes);
            jb.add("total_hangs", total_hangs);
            jb.add("cpu_usage_pct", cpu_usage);
            jb.add("memory_usage_mb", memory_usage_mb);
            jb.add("num_coverage_lines", coverage_lines);
            jb.add("num_coverage_branches", coverage_branches);
            jb.add("num_coverage_functions", coverage_functions);
            jb.add("corpus_size", corpus_size);
            jb.add("corpus_diversity_score", corpus_diversity_score);
            jb.add("total_mutations_executed", total_mutations_executed);
            jb.add("total_mutations_successful", total_mutations_successful);
            jb.add("mutation_success_rate", mutation_success_rate);
            jb.add("new_features_discovered", new_features_discovered);
            emit_jsonl_("execution_events", jb);
        }
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled || !m_tables_initialized.load()) return;

    clickhouse::Block b;

    // Append common columns first
    append_common_columns_to_block_(&b);

    // Table-specific columns
    APPEND_DATETIME64_COLUMN(b, "event_time", now_epoch_ms_(), 3);
    APPEND_UINT64_COLUMN(b, "total_executions", total_executions);
    APPEND_UINT64_COLUMN(b, "total_crashes", total_crashes);
    APPEND_UINT64_COLUMN(b, "total_hangs", total_hangs);
    APPEND_FLOAT32_COLUMN(b, "cpu_usage_pct", cpu_usage);
    APPEND_UINT64_COLUMN(b, "memory_usage_mb", memory_usage_mb);
    APPEND_UINT32_COLUMN(b, "num_coverage_lines", coverage_lines);
    APPEND_UINT32_COLUMN(b, "num_coverage_branches", coverage_branches);
    APPEND_UINT32_COLUMN(b, "num_coverage_functions", coverage_functions);
    APPEND_UINT64_COLUMN(b, "corpus_size", corpus_size);
    APPEND_FLOAT32_COLUMN(b, "corpus_diversity_score", corpus_diversity_score);
    APPEND_UINT64_COLUMN(b, "total_mutations_executed", total_mutations_executed);
    APPEND_UINT64_COLUMN(b, "total_mutations_successful", total_mutations_successful);
    APPEND_FLOAT32_COLUMN(b, "mutation_success_rate", mutation_success_rate);
    APPEND_UINT64_COLUMN(b, "new_features_discovered", new_features_discovered);

    // Enqueue for async execution (non-blocking)
    enqueue_insert_("execution_events", &b, "execution metrics");
#endif
}

void MetricsLogger::log_mutation_health(
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
    uint64_t elf_fixup_ok_cnt,
    uint64_t exec_fail_cnt,
    uint64_t verify_cnt,
    uint64_t harness_reject_cnt)
{
    if (vector_enabled_.load()) {
        static const bool s_exec_events_enabled = [] {
            const char* v = std::getenv("SOLFUZZ_EXECUTION_EVENTS_ENABLE");
            return v && std::string(v) == "1";
        }();
        if (s_exec_events_enabled) {
            JsonBuilder jb;
            add_common_fields_(jb);
            jb.add_timestamp("event_time", now_epoch_ms());
            jb.add("fuzzer_state", std::string(""));
            jb.add("dry_run_tested", static_cast<uint64_t>(0));
            jb.add("dry_run_total", static_cast<uint64_t>(0));
            jb.add("total_executions", total_executions);
            jb.add("execs_delta", static_cast<uint64_t>(0));
            jb.add("total_crashes", static_cast<uint64_t>(0));
            jb.add("total_hangs", static_cast<uint64_t>(0));
            jb.add("cpu_usage_pct", 0.0f);
            jb.add("memory_usage_mb", static_cast<uint64_t>(0));
            jb.add("num_coverage_lines", static_cast<uint32_t>(0));
            jb.add("num_coverage_branches", static_cast<uint32_t>(0));
            jb.add("num_coverage_functions", static_cast<uint32_t>(0));
            jb.add("coverage_cmp", static_cast<uint64_t>(0));
            jb.add("coverage_edge_bucket", static_cast<uint64_t>(0));
            jb.add("corpus_size", static_cast<uint64_t>(0));
            jb.add("corpus_diversity_score", 0.0f);
            jb.add("total_mutations_executed", static_cast<uint64_t>(0));
            jb.add("total_mutations_successful", static_cast<uint64_t>(0));
            jb.add("mutation_success_rate", rate);
            jb.add("new_features_discovered", static_cast<uint64_t>(0));
            jb.add("proto_parse_calls", proto_parse_calls);
            jb.add("proto_parse_successes", proto_parse_successes);
            jb.add("custom_mutator_calls", custom_mutator_calls);
            jb.add("custom_mutator_successes", custom_mutator_successes);
            jb.add("sched_total", static_cast<uint64_t>(0));
            jb.add("repeat_pct", 0.0f);
            jb.add("high_priority_pct", 0.0f);
            jb.add("low_priority_pct", 0.0f);
            jb.add("phase2_pct", 0.0f);
            jb.add("avg_energy", static_cast<uint64_t>(0));
            jb.add("avg_iters", 0.0f);
            jb.add("max_iters", static_cast<uint64_t>(0));
            jb.add("energy_min", static_cast<uint64_t>(0));
            jb.add("energy_max", static_cast<uint64_t>(0));
            jb.add("novelty_decay_cnt", static_cast<uint64_t>(0));
            jb.add("fresh_boost_cnt", static_cast<uint64_t>(0));
            jb.add("stale_penalty_cnt", static_cast<uint64_t>(0));
            jb.add("diminishing_cnt", static_cast<uint64_t>(0));
            jb.add("depth_penalty_cnt", static_cast<uint64_t>(0));
            jb.add("corpus_count", static_cast<uint64_t>(0));
            jb.add("global_avg_energy", static_cast<uint64_t>(0));
            jb.add("exec_avg_us", static_cast<uint64_t>(0));
            jb.add("exec_max_us", static_cast<uint64_t>(0));
            jb.add("slow_exec_cnt", static_cast<uint64_t>(0));
            jb.add("mut_hit_rate_pct", 0.0f);
            jb.add("plateau_secs", static_cast<uint64_t>(0));
            jb.add("queue_wraps", static_cast<uint64_t>(0));
            jb.add("max_depth", static_cast<uint32_t>(0));
            jb.add("unique_crashes", static_cast<uint64_t>(0));
            jb.add("timeouts", static_cast<uint64_t>(0));
            jb.add("fertile_boosts", static_cast<uint64_t>(0));
            jb.add("saturated_lineages", static_cast<uint64_t>(0));
            jb.add("explore_selects", static_cast<uint64_t>(0));
            jb.add("secs_since_crash", static_cast<uint64_t>(0));
            jb.add("stagnation_secs", static_cast<uint64_t>(0));
            jb.add("corpus_growth", static_cast<uint64_t>(0));
            jb.add("inputs_truncated_too_large", static_cast<uint64_t>(0));
            jb.add("proto_round_cnt", proto_round_cnt);
            jb.add("proto_scan_ok_cnt", proto_scan_ok_cnt);
            jb.add("total_round_cnt", total_round_cnt);
            // Column names use "lpm_" prefix for backward-compatible schema
            jb.add("lpm_mutate_cnt", kutator_mutate_cnt);
            jb.add("lpm_crossover_cnt", kutator_crossover_cnt);
            jb.add("lpm_parse_success_cnt", kutator_parse_success_cnt);
            jb.add("lpm_parse_fail_cnt", kutator_parse_fail_cnt);
            jb.add("encode_overflow_cnt", encode_overflow_cnt);
            jb.add("no_candidates_cnt", no_candidates_cnt);
            for (uint32_t k = 0; k < kind_num; k++) {
                jb.add(sanitize_kind_col(kind_names[k]).c_str(), kind_counts[k]);
            }
            jb.add("elf_fixup_ok_cnt", elf_fixup_ok_cnt);
            jb.add("exec_fail_cnt", exec_fail_cnt);
            jb.add("verify_cnt", verify_cnt);
            jb.add("harness_reject_cnt", harness_reject_cnt);
            emit_jsonl_("execution_events", jb);
        }
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled || !m_tables_initialized.load()) return;

    clickhouse::Block b;
    append_common_columns_to_block_(&b);

    APPEND_DATETIME64_COLUMN(b, "event_time", now_epoch_ms_(), 3);
    APPEND_UINT64_COLUMN(b, "total_executions", total_executions);
    APPEND_UINT64_COLUMN(b, "total_crashes", 0);
    APPEND_UINT64_COLUMN(b, "total_hangs", 0);
    APPEND_FLOAT32_COLUMN(b, "cpu_usage_pct", 0.0f);
    APPEND_UINT64_COLUMN(b, "memory_usage_mb", 0);
    APPEND_UINT32_COLUMN(b, "num_coverage_lines", 0);
    APPEND_UINT32_COLUMN(b, "num_coverage_branches", 0);
    APPEND_UINT32_COLUMN(b, "num_coverage_functions", 0);
    APPEND_UINT64_COLUMN(b, "coverage_cmp", 0);
    APPEND_UINT64_COLUMN(b, "coverage_edge_bucket", 0);
    APPEND_UINT64_COLUMN(b, "corpus_size", 0);
    APPEND_FLOAT32_COLUMN(b, "corpus_diversity_score", 0.0f);
    APPEND_UINT64_COLUMN(b, "total_mutations_executed", 0);
    APPEND_UINT64_COLUMN(b, "total_mutations_successful", 0);
    APPEND_FLOAT32_COLUMN(b, "mutation_success_rate", rate);
    APPEND_UINT64_COLUMN(b, "new_features_discovered", 0);
    APPEND_UINT64_COLUMN(b, "execs_delta", 0);

    // SCHED/DECAY/HEALTH/DIFF-FUZZ columns (not available in this call path)
    APPEND_UINT64_COLUMN(b, "sched_total", 0);
    APPEND_FLOAT32_COLUMN(b, "repeat_pct", 0.0f);
    APPEND_FLOAT32_COLUMN(b, "high_priority_pct", 0.0f);
    APPEND_FLOAT32_COLUMN(b, "low_priority_pct", 0.0f);
    APPEND_FLOAT32_COLUMN(b, "phase2_pct", 0.0f);
    APPEND_UINT64_COLUMN(b, "avg_energy", 0);
    APPEND_FLOAT32_COLUMN(b, "avg_iters", 0.0f);
    APPEND_UINT64_COLUMN(b, "max_iters", 0);
    APPEND_UINT64_COLUMN(b, "energy_min", 0);
    APPEND_UINT64_COLUMN(b, "energy_max", 0);
    APPEND_UINT64_COLUMN(b, "novelty_decay_cnt", 0);
    APPEND_UINT64_COLUMN(b, "fresh_boost_cnt", 0);
    APPEND_UINT64_COLUMN(b, "stale_penalty_cnt", 0);
    APPEND_UINT64_COLUMN(b, "diminishing_cnt", 0);
    APPEND_UINT64_COLUMN(b, "depth_penalty_cnt", 0);
    APPEND_UINT64_COLUMN(b, "corpus_count", 0);
    APPEND_UINT64_COLUMN(b, "global_avg_energy", 0);
    APPEND_UINT64_COLUMN(b, "exec_avg_us", 0);
    APPEND_UINT64_COLUMN(b, "exec_max_us", 0);
    APPEND_UINT64_COLUMN(b, "slow_exec_cnt", 0);
    APPEND_FLOAT32_COLUMN(b, "mut_hit_rate_pct", 0.0f);
    APPEND_UINT64_COLUMN(b, "plateau_secs", 0);
    APPEND_UINT64_COLUMN(b, "queue_wraps", 0);
    APPEND_UINT32_COLUMN(b, "max_depth", 0);
    APPEND_UINT64_COLUMN(b, "unique_crashes", 0);
    APPEND_UINT64_COLUMN(b, "timeouts", 0);
    APPEND_UINT64_COLUMN(b, "fertile_boosts", 0);
    APPEND_UINT64_COLUMN(b, "saturated_lineages", 0);
    APPEND_UINT64_COLUMN(b, "explore_selects", 0);
    APPEND_UINT64_COLUMN(b, "secs_since_crash", 0);
    APPEND_UINT64_COLUMN(b, "stagnation_secs", 0);
    APPEND_UINT64_COLUMN(b, "corpus_growth", 0);
    APPEND_STRING_COLUMN(b, "fuzzer_state", std::string(""));
    APPEND_UINT64_COLUMN(b, "dry_run_tested", 0);
    APPEND_UINT64_COLUMN(b, "dry_run_total", 0);
    APPEND_UINT64_COLUMN(b, "inputs_truncated_too_large", 0);

    // Mutation health columns (from function params)
    APPEND_UINT64_COLUMN(b, "proto_parse_calls", proto_parse_calls);
    APPEND_UINT64_COLUMN(b, "proto_parse_successes", proto_parse_successes);
    APPEND_UINT64_COLUMN(b, "custom_mutator_calls", custom_mutator_calls);
    APPEND_UINT64_COLUMN(b, "custom_mutator_successes", custom_mutator_successes);
    APPEND_UINT64_COLUMN(b, "proto_round_cnt", proto_round_cnt);
    APPEND_UINT64_COLUMN(b, "proto_scan_ok_cnt", proto_scan_ok_cnt);
    APPEND_UINT64_COLUMN(b, "total_round_cnt", total_round_cnt);
    APPEND_UINT64_COLUMN(b, "lpm_mutate_cnt", kutator_mutate_cnt);
    APPEND_UINT64_COLUMN(b, "lpm_crossover_cnt", kutator_crossover_cnt);
    APPEND_UINT64_COLUMN(b, "lpm_parse_success_cnt", kutator_parse_success_cnt);
    APPEND_UINT64_COLUMN(b, "lpm_parse_fail_cnt", kutator_parse_fail_cnt);
    APPEND_UINT64_COLUMN(b, "encode_overflow_cnt", encode_overflow_cnt);
    APPEND_UINT64_COLUMN(b, "no_candidates_cnt", no_candidates_cnt);
    for (uint32_t k = 0; k < kind_num; k++) {
        std::string col = sanitize_kind_col(kind_names[k]);
        APPEND_UINT64_COLUMN(b, col.c_str(), kind_counts[k]);
    }
    APPEND_UINT64_COLUMN(b, "elf_fixup_ok_cnt", elf_fixup_ok_cnt);
    APPEND_UINT64_COLUMN(b, "exec_fail_cnt", exec_fail_cnt);
    APPEND_UINT64_COLUMN(b, "verify_cnt", verify_cnt);
    APPEND_UINT64_COLUMN(b, "harness_reject_cnt", harness_reject_cnt);

    // Capture kind_names for lazy column creation on the logger thread.
    std::vector<std::string> names_vec;
    names_vec.reserve(kind_num);
    for (uint32_t k = 0; k < kind_num; k++) {
        names_vec.emplace_back(kind_names[k] ? kind_names[k] : "unknown");
    }
    auto block = std::make_shared<clickhouse::Block>(std::move(b));
    enqueue_log_([this, block, names_vec = std::move(names_vec)]() {
        // Lazily add any new kind columns before inserting
        std::vector<const char*> ptrs;
        ptrs.reserve(names_vec.size());
        for (const auto& s : names_vec) ptrs.push_back(s.c_str());
        ensure_kind_columns_(ptrs.data(), static_cast<uint32_t>(ptrs.size()));

        insert_with_retry_("execution_events", block.get(), "mutation_health");
    }, "mutation_health");
#else
    (void)total_executions; (void)proto_parse_calls; (void)proto_parse_successes;
    (void)custom_mutator_calls; (void)custom_mutator_successes; (void)rate;
    (void)proto_round_cnt; (void)proto_scan_ok_cnt; (void)total_round_cnt;
    (void)kutator_mutate_cnt; (void)kutator_crossover_cnt; (void)kutator_parse_success_cnt; (void)kutator_parse_fail_cnt;
    (void)encode_overflow_cnt; (void)no_candidates_cnt;
    (void)kind_counts; (void)kind_names; (void)kind_num;
    (void)elf_fixup_ok_cnt; (void)exec_fail_cnt; (void)verify_cnt; (void)harness_reject_cnt;
#endif
}

void MetricsLogger::log_bug_discovery(
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
    const std::string& description)
{
    std::cerr << "[MetricsLogger] Bug discovered: " << bug_id 
              << ", type: " << bug_type 
              << ", severity: " << severity 
              << ", file: " << file << ":" << line 
              << ", description: " << description << std::endl;

    if (vector_enabled_.load()) {
        JsonBuilder jb;
        add_common_fields_(jb);
        jb.add("bug_id", bug_id);
        jb.add_timestamp("event_time", now_epoch_ms());
        jb.add("event_type", std::string("discovered"));
        jb.add("component", fuzz_target_);
        jb.add("file_path", file);
        jb.add("function_name", function);
        jb.add("line_number", line < 0 ? static_cast<uint32_t>(0) : static_cast<uint32_t>(line));
        jb.add("bug_type", bug_type);
        jb.add("severity", severity);
        jb.add("status", status);
        jb.add("reproduction_time_ms", static_cast<uint32_t>(reproduction_time_ms));
        jb.add("input_size_bytes", static_cast<uint32_t>(input_size));
        jb.add("stack_trace", std::string(""));
        jb.add("fix_commit", std::string(""));
        emit_jsonl_("bug_events", jb);
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled) return;
    try {
        ensure_client_();
    } catch (...) {
        // Connection failed, disable future attempts
        return;
    }

    clickhouse::Block b;

    // Append common columns first
    append_common_columns_to_block_(&b);

    // Table-specific columns
    APPEND_STRING_COLUMN(b, "bug_id", bug_id);
    APPEND_DATETIME64_COLUMN(b, "event_time", now_epoch_ms_(), 3);
    APPEND_STRING_COLUMN(b, "event_type", "discovered");
    APPEND_STRING_COLUMN(b, "component", fuzz_target_);
    APPEND_STRING_COLUMN(b, "file_path", file);
    APPEND_STRING_COLUMN(b, "function_name", function);
    APPEND_UINT32_COLUMN(b, "line_number", line < 0 ? 0u : static_cast<uint32_t>(line));
    APPEND_STRING_COLUMN(b, "bug_type", bug_type);
    APPEND_STRING_COLUMN(b, "severity", severity);
    APPEND_STRING_COLUMN(b, "status", status);
    APPEND_UINT32_COLUMN(b, "reproduction_time_ms", static_cast<uint32_t>(reproduction_time_ms));
    APPEND_UINT32_COLUMN(b, "input_size_bytes", static_cast<uint32_t>(input_size));
    APPEND_STRING_COLUMN(b, "stack_trace", std::string());
    APPEND_STRING_COLUMN(b, "fix_commit", std::string());

    enqueue_insert_("bug_events", &b, "bug event for " + bug_id);
    std::cerr << "[MetricsLogger] Enqueued bug discovery: " << bug_id << std::endl;
#endif
}

void MetricsLogger::log_mismatch(const std::string& category,
                                  const std::string& expected,
                                  const std::string& actual,
                                  const std::string& details) {
    std::cerr << "[MetricsLogger] Mismatch - " << category
              << ": expected='" << expected
              << "' actual='" << actual << "'";
    if (!details.empty()) {
        std::cerr << " details='" << details << "'";
    }
    std::cerr << std::endl;

    if (vector_enabled_.load()) {
        JsonBuilder jb;
        add_common_fields_(jb);
        jb.add_timestamp("event_time", now_epoch_ms());
        jb.add("category", category);
        jb.add("expected", expected);
        jb.add("actual", actual);
        jb.add("details", details);
        emit_jsonl_("mismatch_events", jb);
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled) return;
    try {
        ensure_client_();
    } catch (...) {
        // Connection failed, disable future attempts
        return;
    }

    clickhouse::Block b;

    // Append common columns first
    append_common_columns_to_block_(&b);

    // Table-specific columns
    APPEND_DATETIME64_COLUMN(b, "event_time", now_epoch_ms_(), 3);
    APPEND_STRING_COLUMN(b, "category", category);
    APPEND_STRING_COLUMN(b, "expected", expected);
    APPEND_STRING_COLUMN(b, "actual", actual);
    APPEND_STRING_COLUMN(b, "details", details);

    enqueue_insert_("mismatch_events", &b, "mismatch event: " + category);
    std::cerr << "[MetricsLogger] Enqueued mismatch event: " << category << std::endl;
#endif
}

// Coverage events

void MetricsLogger::log_coverage_event(
    /* const std::string& session_id, */
    const std::string& component,
    const std::string& file_path,
    const std::string& function_name,
    uint32_t start_line,
    uint32_t end_line,
    const std::string& coverage_type,
    uint64_t hits,
    const std::vector<uint32_t>& line_numbers,
    const std::vector<uint32_t>& line_hits,
    const std::string& target_name)
{
    if (vector_enabled_.load()) {
        JsonBuilder jb;
        add_common_fields_(jb);
        jb.add_timestamp("event_time", now_epoch_ms());
        jb.add("component", component);
        jb.add("file_path", normalize_path(file_path));
        jb.add("function_name", function_name);
        jb.add("start_line", start_line);
        jb.add("end_line", end_line);
        jb.add("coverage_type", coverage_type);
        jb.add("hits", hits);
        jb.add_uint32_array("line_hits", line_hits);
        jb.add_uint32_array("line_numbers", line_numbers);
        emit_jsonl_("coverage_events", jb);
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled) return;
    try {
        ensure_client_();
    } catch (...) {
        // Connection failed, disable future attempts
        return;
    }

    clickhouse::Block b;

    // Append common columns first
    append_common_columns_to_block_(&b);

    // Table-specific columns
    APPEND_DATETIME64_COLUMN(b, "event_time", now_epoch_ms_(), 3);
    APPEND_STRING_COLUMN(b, "component", component);
    APPEND_STRING_COLUMN(b, "file_path", normalize_path(file_path));
    APPEND_STRING_COLUMN(b, "function_name", function_name);
    APPEND_UINT32_COLUMN(b, "start_line", start_line);
    APPEND_UINT32_COLUMN(b, "end_line", end_line);
    APPEND_STRING_COLUMN(b, "coverage_type", coverage_type);
    APPEND_UINT64_COLUMN(b, "hits", hits);
    
    // Array columns need special handling - must use explicit offsets for proper row count
    {
        auto inner_uint = std::make_shared<clickhouse::ColumnUInt32>();
        auto offsets = std::make_shared<clickhouse::ColumnUInt64>();
        for (auto v : line_hits) {
            inner_uint->Append(v);
        }
        offsets->Append(inner_uint->Size());  // Mark end of this row's array
        auto c_line_hits = std::make_shared<clickhouse::ColumnArray>(inner_uint, offsets);
        b.AppendColumn("line_hits", c_line_hits);
    }
    {
        auto inner_uint = std::make_shared<clickhouse::ColumnUInt32>();
        auto offsets = std::make_shared<clickhouse::ColumnUInt64>();
        for (auto v : line_numbers) {
            inner_uint->Append(v);
        }
        offsets->Append(inner_uint->Size());  // Mark end of this row's array
        auto c_line_nums = std::make_shared<clickhouse::ColumnArray>(inner_uint, offsets);
        b.AppendColumn("line_numbers", c_line_nums);
    }

    enqueue_insert_("coverage_events", &b, "coverage event: " + file_path + "::" + function_name);
    std::cerr << "[MetricsLogger] Enqueued coverage event: " 
              << file_path << "::" << function_name << std::endl;
#endif
}

void MetricsLogger::log_coverage_events_batch(
    /* const std::string& session_id, */
    const std::string& component,
    const std::vector<std::tuple<
        std::string,
        std::string,
        uint32_t,
        uint32_t,
        std::string,
        uint64_t,
        std::vector<uint32_t>,
        std::vector<uint32_t>
    >>& events,
    const std::string& target_name)
{
#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled) {
        return;
    }
    
    if (events.empty()) {
        return;
    }
    
    // Ensure connection is alive before batch insert (critical operation, especially at shutdown)
    ensure_connection();
    
    if (!client_) {
        std::cerr << "[MetricsLogger] WARNING: Cannot log coverage events batch - no connection available" << std::endl;
        return;
    }

    const int64_t ts = now_epoch_ms_();

    // Create columns for all rows
    clickhouse::Block b;
    
    // Create common columns for batch (repeated for each row)
    auto c_session_id = std::make_shared<clickhouse::ColumnString>();
    auto c_fuzzer_name = std::make_shared<clickhouse::ColumnString>();
    auto c_harness_name = std::make_shared<clickhouse::ColumnString>();
    auto c_fuzz_target = std::make_shared<clickhouse::ColumnString>();
    auto nested_target_names = std::make_shared<clickhouse::ColumnString>();
    auto nested_target_paths = std::make_shared<clickhouse::ColumnString>();
    auto offsets_target_names = std::make_shared<clickhouse::ColumnUInt64>();
    auto offsets_target_paths = std::make_shared<clickhouse::ColumnUInt64>();
    auto c_program_id = std::make_shared<clickhouse::ColumnString>();
    auto c_syscall_name = std::make_shared<clickhouse::ColumnString>();
    auto c_user_name = std::make_shared<clickhouse::ColumnString>();
    auto c_host_name = std::make_shared<clickhouse::ColumnString>();
    auto c_task_id = std::make_shared<clickhouse::ColumnString>();
    auto c_bundle_id = std::make_shared<clickhouse::ColumnString>();
    auto c_asset_id = std::make_shared<clickhouse::ColumnString>();
    auto c_organization = std::make_shared<clickhouse::ColumnString>();
    auto c_project = std::make_shared<clickhouse::ColumnString>();
    auto c_lineage_name = std::make_shared<clickhouse::ColumnString>();
    auto c_corpus_group = std::make_shared<clickhouse::ColumnString>();
    auto c_task_type = std::make_shared<clickhouse::ColumnString>();
    
    auto c_event_time = std::make_shared<clickhouse::ColumnDateTime64>(3);  // milliseconds since epoch
    auto c_component  = std::make_shared<clickhouse::ColumnString>();
    auto c_file_path  = std::make_shared<clickhouse::ColumnString>();
    auto c_func_name  = std::make_shared<clickhouse::ColumnString>();
    auto c_start_line = std::make_shared<clickhouse::ColumnUInt32>();
    auto c_end_line   = std::make_shared<clickhouse::ColumnUInt32>();
    auto c_cov_type   = std::make_shared<clickhouse::ColumnString>();
    auto c_hits       = std::make_shared<clickhouse::ColumnUInt64>();
    
    // For array columns, build nested columns and offsets manually
    auto nested_line_hits = std::make_shared<clickhouse::ColumnUInt32>();
    auto nested_line_nums = std::make_shared<clickhouse::ColumnUInt32>();
    auto offsets_line_hits = std::make_shared<clickhouse::ColumnUInt64>();
    auto offsets_line_nums = std::make_shared<clickhouse::ColumnUInt64>();

    // Append data for each event
    for (const auto& e : events) {
        const auto& file_path = std::get<0>(e);
        const auto& function_name = std::get<1>(e);
        uint32_t start_line = std::get<2>(e);
        uint32_t end_line = std::get<3>(e);
        const auto& coverage_type = std::get<4>(e);
        uint64_t hits = std::get<5>(e);
        const auto& line_numbers = std::get<6>(e);
        const auto& line_hits = std::get<7>(e);

        // Append common column values (repeated for each row)
        c_session_id->Append(session_id_);
        c_fuzzer_name->Append(fuzzer_name_);
        c_harness_name->Append(harness_name_);
        c_fuzz_target->Append(fuzz_target_);
        // Build target_names array
        for (const auto& s : target_names_) {
            nested_target_names->Append(s);
        }
        offsets_target_names->Append(nested_target_names->Size());
        // Build target_paths array
        for (const auto& s : target_paths_) {
            nested_target_paths->Append(s);
        }
        offsets_target_paths->Append(nested_target_paths->Size());
        c_program_id->Append(program_id_);
        c_syscall_name->Append(syscall_name_);
        c_user_name->Append(user_name_);
        c_host_name->Append(host_name_);
        c_task_id->Append(task_id_);
        c_bundle_id->Append(bundle_id_);
        c_asset_id->Append(asset_id_);
        c_organization->Append(organization_);
        c_project->Append(project_);
        c_lineage_name->Append(lineage_name_);
        c_corpus_group->Append(corpus_group_);
        c_task_type->Append(task_type_);
        
        // Append table-specific scalar values
        c_event_time->Append(ts);
        c_component->Append(component);
        c_file_path->Append(normalize_path(file_path));  // Normalize for consistent joins
        c_func_name->Append(function_name);
        c_start_line->Append(start_line);
        c_end_line->Append(end_line);
        c_cov_type->Append(coverage_type);
        c_hits->Append(hits);

        // Build array columns: append elements to nested columns and track offsets
        uint64_t hits_offset_before = nested_line_hits->Size();
        for (auto v : line_hits) {
            nested_line_hits->Append(v);
        }
        offsets_line_hits->Append(nested_line_hits->Size());
        
        uint64_t nums_offset_before = nested_line_nums->Size();
        for (auto v : line_numbers) {
            nested_line_nums->Append(v);
        }
        offsets_line_nums->Append(nested_line_nums->Size());
    }
    
    // Create ColumnArray columns from nested columns and offsets
    auto c_target_names = std::make_shared<clickhouse::ColumnArray>(nested_target_names, offsets_target_names);
    auto c_target_paths = std::make_shared<clickhouse::ColumnArray>(nested_target_paths, offsets_target_paths);
    auto c_line_hits = std::make_shared<clickhouse::ColumnArray>(nested_line_hits, offsets_line_hits);
    auto c_line_nums = std::make_shared<clickhouse::ColumnArray>(nested_line_nums, offsets_line_nums);

    // Verify all columns have the same row count before appending to block
    size_t expected_rows = events.size();
    if (c_session_id->Size() != expected_rows) {
        std::cerr << "[MetricsLogger] ERROR: session_id column has wrong size: " 
                  << c_session_id->Size() << " != " << expected_rows << std::endl;
    }
    if (c_line_hits->Size() != expected_rows) {
        std::cerr << "[MetricsLogger] ERROR: line_hits column has wrong size: " 
                  << c_line_hits->Size() << " != " << expected_rows << std::endl;
    }
    if (c_line_nums->Size() != expected_rows) {
        std::cerr << "[MetricsLogger] ERROR: line_nums column has wrong size: " 
                  << c_line_nums->Size() << " != " << expected_rows << std::endl;
    }
    
    // Append all columns to the block (common columns first, then table-specific)
    b.AppendColumn("session_id", c_session_id);
    b.AppendColumn("fuzzer_name", c_fuzzer_name);
    b.AppendColumn("harness_name", c_harness_name);
    b.AppendColumn("fuzz_target", c_fuzz_target);
    b.AppendColumn("target_names", c_target_names);
    b.AppendColumn("target_paths", c_target_paths);
    b.AppendColumn("program_id", c_program_id);
    b.AppendColumn("syscall_name", c_syscall_name);
    b.AppendColumn("user_name", c_user_name);
    b.AppendColumn("host_name", c_host_name);
    b.AppendColumn("task_id", c_task_id);
    b.AppendColumn("bundle_id", c_bundle_id);
    b.AppendColumn("asset_id", c_asset_id);
    b.AppendColumn("organization", c_organization);
    b.AppendColumn("project", c_project);
    b.AppendColumn("lineage_name", c_lineage_name);
    b.AppendColumn("corpus_group", c_corpus_group);
    b.AppendColumn("task_type", c_task_type);
    b.AppendColumn("event_time", c_event_time);
    b.AppendColumn("component", c_component);
    b.AppendColumn("file_path", c_file_path);
    b.AppendColumn("function_name", c_func_name);
    b.AppendColumn("start_line", c_start_line);
    b.AppendColumn("end_line", c_end_line);
    b.AppendColumn("coverage_type", c_cov_type);
    b.AppendColumn("hits", c_hits);
    b.AppendColumn("line_hits", c_line_hits);
    b.AppendColumn("line_numbers", c_line_nums);

    // Single insert for all rows - enqueue for async execution
    std::string batch_desc = "batch of " + std::to_string(events.size()) + " coverage events";
    enqueue_insert_("coverage_events", &b, batch_desc);
    std::cerr << "[MetricsLogger] Enqueued batch of " << events.size() 
              << " coverage events for async insertion" << std::endl;
#endif
}

void MetricsLogger::log_execution_coverage(
    uint64_t execution_id,
    const std::string& component,
    const std::vector<std::tuple<
        std::string,   // file_path
        std::string,   // function_name
        uint32_t,      // start_line
        uint32_t,      // end_line
        std::string    // coverage_type
    >>& covered_items)
{
#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled || covered_items.empty()) return;
    
    try {
        ensure_client_();
    } catch (...) {
        return;
    }

    const int64_t ts = now_epoch_ms_();

    // Create columns for all rows
    clickhouse::Block b;
    
    // Create common columns for batch (repeated for each row)
    auto c_session_id = std::make_shared<clickhouse::ColumnString>();
    auto c_fuzzer_name = std::make_shared<clickhouse::ColumnString>();
    auto c_harness_name = std::make_shared<clickhouse::ColumnString>();
    auto c_fuzz_target = std::make_shared<clickhouse::ColumnString>();
    auto nested_target_names = std::make_shared<clickhouse::ColumnString>();
    auto nested_target_paths = std::make_shared<clickhouse::ColumnString>();
    auto offsets_target_names = std::make_shared<clickhouse::ColumnUInt64>();
    auto offsets_target_paths = std::make_shared<clickhouse::ColumnUInt64>();
    auto c_program_id = std::make_shared<clickhouse::ColumnString>();
    auto c_syscall_name = std::make_shared<clickhouse::ColumnString>();
    auto c_user_name = std::make_shared<clickhouse::ColumnString>();
    auto c_host_name = std::make_shared<clickhouse::ColumnString>();
    auto c_task_id = std::make_shared<clickhouse::ColumnString>();
    auto c_bundle_id = std::make_shared<clickhouse::ColumnString>();
    auto c_asset_id = std::make_shared<clickhouse::ColumnString>();
    auto c_organization = std::make_shared<clickhouse::ColumnString>();
    auto c_project = std::make_shared<clickhouse::ColumnString>();
    auto c_lineage_name = std::make_shared<clickhouse::ColumnString>();
    auto c_corpus_group = std::make_shared<clickhouse::ColumnString>();
    auto c_task_type = std::make_shared<clickhouse::ColumnString>();
    
    auto c_event_time = std::make_shared<clickhouse::ColumnDateTime64>(3);
    auto c_execution_id = std::make_shared<clickhouse::ColumnUInt64>();
    auto c_component = std::make_shared<clickhouse::ColumnString>();
    auto c_file_path = std::make_shared<clickhouse::ColumnString>();
    auto c_func_name = std::make_shared<clickhouse::ColumnString>();
    auto c_start_line = std::make_shared<clickhouse::ColumnUInt32>();
    auto c_end_line = std::make_shared<clickhouse::ColumnUInt32>();
    auto c_cov_type = std::make_shared<clickhouse::ColumnString>();

    // Append data for each covered item
    for (const auto& item : covered_items) {
        const auto& file_path = std::get<0>(item);
        const auto& function_name = std::get<1>(item);
        uint32_t start_line = std::get<2>(item);
        uint32_t end_line = std::get<3>(item);
        const auto& coverage_type = std::get<4>(item);

        // Append common column values (repeated for each row)
        c_session_id->Append(session_id_);
        c_fuzzer_name->Append(fuzzer_name_);
        c_harness_name->Append(harness_name_);
        c_fuzz_target->Append(fuzz_target_);
        // Build target_names array
        for (const auto& s : target_names_) {
            nested_target_names->Append(s);
        }
        offsets_target_names->Append(nested_target_names->Size());
        // Build target_paths array
        for (const auto& s : target_paths_) {
            nested_target_paths->Append(s);
        }
        offsets_target_paths->Append(nested_target_paths->Size());
        c_program_id->Append(program_id_);
        c_syscall_name->Append(syscall_name_);
        c_user_name->Append(user_name_);
        c_host_name->Append(host_name_);
        c_task_id->Append(task_id_);
        c_bundle_id->Append(bundle_id_);
        c_asset_id->Append(asset_id_);
        c_organization->Append(organization_);
        c_project->Append(project_);
        c_lineage_name->Append(lineage_name_);
        c_corpus_group->Append(corpus_group_);
        c_task_type->Append(task_type_);
        
        // Append table-specific values
        c_event_time->Append(ts);
        c_execution_id->Append(execution_id);
        c_component->Append(component);
        c_file_path->Append(normalize_path(file_path));  // Normalize for consistent joins
        c_func_name->Append(function_name);
        c_start_line->Append(start_line);
        c_end_line->Append(end_line);
        c_cov_type->Append(coverage_type);
    }
    
    // Create ColumnArray columns from nested columns and offsets
    auto c_target_names = std::make_shared<clickhouse::ColumnArray>(nested_target_names, offsets_target_names);
    auto c_target_paths = std::make_shared<clickhouse::ColumnArray>(nested_target_paths, offsets_target_paths);

    // Append all columns to the block (common columns first, then table-specific)
    b.AppendColumn("session_id", c_session_id);
    b.AppendColumn("fuzzer_name", c_fuzzer_name);
    b.AppendColumn("harness_name", c_harness_name);
    b.AppendColumn("fuzz_target", c_fuzz_target);
    b.AppendColumn("target_names", c_target_names);
    b.AppendColumn("target_paths", c_target_paths);
    b.AppendColumn("program_id", c_program_id);
    b.AppendColumn("syscall_name", c_syscall_name);
    b.AppendColumn("user_name", c_user_name);
    b.AppendColumn("host_name", c_host_name);
    b.AppendColumn("task_id", c_task_id);
    b.AppendColumn("bundle_id", c_bundle_id);
    b.AppendColumn("asset_id", c_asset_id);
    b.AppendColumn("organization", c_organization);
    b.AppendColumn("project", c_project);
    b.AppendColumn("lineage_name", c_lineage_name);
    b.AppendColumn("corpus_group", c_corpus_group);
    b.AppendColumn("task_type", c_task_type);
    b.AppendColumn("event_time", c_event_time);
    b.AppendColumn("execution_id", c_execution_id);
    b.AppendColumn("component", c_component);
    b.AppendColumn("file_path", c_file_path);
    b.AppendColumn("function_name", c_func_name);
    b.AppendColumn("start_line", c_start_line);
    b.AppendColumn("end_line", c_end_line);
    b.AppendColumn("coverage_type", c_cov_type);

    // Single insert for all rows - enqueue for async execution
    std::string batch_desc = "execution coverage for execution_id " + std::to_string(execution_id) + " (" + std::to_string(covered_items.size()) + " items)";
    enqueue_insert_("execution_coverage_events", &b, batch_desc);
#endif
}

void MetricsLogger::log_guard_first_hits(const std::vector<GuardFirstHitEntry>& entries) {
    if (entries.empty() || m_shutting_down.load()) return;

    if (vector_enabled_.load()) {
        int64_t ts = now_epoch_ms();
        for (const auto& entry : entries) {
            JsonBuilder jb;
            add_common_fields_(jb);
            jb.add_timestamp("first_hit_time", ts);
            jb.add("guard_id", static_cast<uint32_t>(entry.guard_id));
            jb.add("file_path", normalize_path(entry.file_path));
            jb.add("function_name", entry.function_name);
            jb.add("line_number", entry.line_number);
            jb.add("module_name", entry.module_name);
            jb.add("coverage_type", entry.coverage_type);
            emit_jsonl_("coverage_guard_first_hits", jb);
        }
    }

#ifdef SOLFUZZ_CLICKHOUSE_ENABLED
    if (!ch_.enabled) return;

    // Single timestamp for entire batch (when the guards were discovered)
    int64_t ts = now_epoch_ms_();

    clickhouse::Block b;
    
    // Common columns (repeated per row - required for batch insert)
    auto c_session_id = std::make_shared<clickhouse::ColumnString>();
    auto c_fuzzer_name = std::make_shared<clickhouse::ColumnString>();
    auto c_harness_name = std::make_shared<clickhouse::ColumnString>();
    auto c_fuzz_target = std::make_shared<clickhouse::ColumnString>();
    auto nested_target_names = std::make_shared<clickhouse::ColumnString>();
    auto offsets_target_names = std::make_shared<clickhouse::ColumnUInt64>();
    auto c_target_names = std::make_shared<clickhouse::ColumnArray>(
        nested_target_names, offsets_target_names);
    auto nested_target_paths = std::make_shared<clickhouse::ColumnString>();
    auto offsets_target_paths = std::make_shared<clickhouse::ColumnUInt64>();
    auto c_target_paths = std::make_shared<clickhouse::ColumnArray>(
        nested_target_paths, offsets_target_paths);
    auto c_program_id = std::make_shared<clickhouse::ColumnString>();
    auto c_syscall_name = std::make_shared<clickhouse::ColumnString>();
    auto c_user_name = std::make_shared<clickhouse::ColumnString>();
    auto c_host_name = std::make_shared<clickhouse::ColumnString>();
    auto c_task_id = std::make_shared<clickhouse::ColumnString>();
    auto c_bundle_id = std::make_shared<clickhouse::ColumnString>();
    auto c_asset_id = std::make_shared<clickhouse::ColumnString>();
    auto c_organization = std::make_shared<clickhouse::ColumnString>();
    auto c_project = std::make_shared<clickhouse::ColumnString>();
    auto c_lineage_name = std::make_shared<clickhouse::ColumnString>();
    auto c_corpus_group = std::make_shared<clickhouse::ColumnString>();
    auto c_task_type = std::make_shared<clickhouse::ColumnString>();
    
    // Table-specific columns
    auto c_first_hit_time = std::make_shared<clickhouse::ColumnDateTime64>(3);
    auto c_guard_id = std::make_shared<clickhouse::ColumnUInt32>();
    auto c_file_path = std::make_shared<clickhouse::ColumnString>();
    auto c_func_name = std::make_shared<clickhouse::ColumnString>();
    auto c_line_number = std::make_shared<clickhouse::ColumnUInt32>();
    auto c_module_name = std::make_shared<clickhouse::ColumnString>();
    auto c_cov_type = std::make_shared<clickhouse::ColumnString>();

    // Append data for each entry
    for (const auto& entry : entries) {
        // Append common column values (repeated for each row)
        c_session_id->Append(session_id_);
        c_fuzzer_name->Append(fuzzer_name_);
        c_harness_name->Append(harness_name_);
        c_fuzz_target->Append(fuzz_target_);
        // Build target_names array
        for (const auto& s : target_names_) {
            nested_target_names->Append(s);
        }
        offsets_target_names->Append(nested_target_names->Size());
        // Build target_paths array
        for (const auto& s : target_paths_) {
            nested_target_paths->Append(s);
        }
        offsets_target_paths->Append(nested_target_paths->Size());
        c_program_id->Append(program_id_);
        c_syscall_name->Append(syscall_name_);
        c_user_name->Append(user_name_);
        c_host_name->Append(host_name_);
        c_task_id->Append(task_id_);
        c_bundle_id->Append(bundle_id_);
        c_asset_id->Append(asset_id_);
        c_organization->Append(organization_);
        c_project->Append(project_);
        c_lineage_name->Append(lineage_name_);
        c_corpus_group->Append(corpus_group_);
        c_task_type->Append(task_type_);
        
        // Append table-specific values
        c_first_hit_time->Append(ts);
        c_guard_id->Append(static_cast<uint32_t>(entry.guard_id));
        c_file_path->Append(normalize_path(entry.file_path));  // Normalize for consistent joins
        c_func_name->Append(entry.function_name);
        c_line_number->Append(entry.line_number);
        c_module_name->Append(entry.module_name);
        c_cov_type->Append(entry.coverage_type);
    }

    // Build block with all columns
    b.AppendColumn("session_id", c_session_id);
    b.AppendColumn("fuzzer_name", c_fuzzer_name);
    b.AppendColumn("harness_name", c_harness_name);
    b.AppendColumn("fuzz_target", c_fuzz_target);
    b.AppendColumn("target_names", c_target_names);
    b.AppendColumn("target_paths", c_target_paths);
    b.AppendColumn("program_id", c_program_id);
    b.AppendColumn("syscall_name", c_syscall_name);
    b.AppendColumn("user_name", c_user_name);
    b.AppendColumn("host_name", c_host_name);
    b.AppendColumn("task_id", c_task_id);
    b.AppendColumn("bundle_id", c_bundle_id);
    b.AppendColumn("asset_id", c_asset_id);
    b.AppendColumn("organization", c_organization);
    b.AppendColumn("project", c_project);
    b.AppendColumn("lineage_name", c_lineage_name);
    b.AppendColumn("corpus_group", c_corpus_group);
    b.AppendColumn("task_type", c_task_type);
    b.AppendColumn("first_hit_time", c_first_hit_time);
    b.AppendColumn("guard_id", c_guard_id);
    b.AppendColumn("file_path", c_file_path);
    b.AppendColumn("function_name", c_func_name);
    b.AppendColumn("line_number", c_line_number);
    b.AppendColumn("module_name", c_module_name);
    b.AppendColumn("coverage_type", c_cov_type);

    // Single insert for all rows - enqueue for async execution
    std::string batch_desc = "guard first-hits batch (" + std::to_string(entries.size()) + " entries)";
    enqueue_insert_("coverage_guard_first_hits", &b, batch_desc);
#endif
}

} // namespace sol_compat
