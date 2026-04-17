#include "fuzzing_session.h"
#include "metrics_logger.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <signal.h>
#include <cstdlib>
#include <pwd.h>
#include <cstring>
#include <sys/resource.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <algorithm>

namespace sol_compat {

// Helper to get environment variable with fallback
static std::string getenv_or(const char* k, const char* dflt) {
    const char* v = std::getenv(k);
    return (v && *v) ? std::string(v) : std::string(dflt);
}

// Helper to get UNIX username
static std::string get_unix_username() {
    const char* env_user = std::getenv("USER");
    if (env_user && *env_user) {
        return std::string(env_user);
    }
    // Fallback to getpwuid
    struct passwd* pw = getpwuid(geteuid());
    if (pw && pw->pw_name) {
        return std::string(pw->pw_name);
    }
    return "unknown";
}

// Helper to get system hostname
static std::string get_hostname() {
    char hostname_buf[256];
    if (gethostname(hostname_buf, sizeof(hostname_buf)) == 0) {
        return std::string(hostname_buf);
    }
    return "unknown";
}

// Static members
FuzzingSession* FuzzingSession::s_instance = nullptr;
static std::atomic<bool> s_shutdown_in_progress{false};

FuzzingSession& FuzzingSession::instance() {
    if (!s_instance) {
        s_instance = new FuzzingSession();
    }
    return *s_instance;
}

void FuzzingSession::initialize(const std::string& fuzz_target_name,
                                const std::vector<std::string>& target_names,
                                const std::string& program_id,
                                const std::string& syscall_name) {
    // Guard against multiple initialization in the same process
    if (m_initialized) {
        if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
            std::ofstream dbg(debug_file, std::ios::app);
            dbg << "[FuzzingSession] initialize() already called (same process), skipping re-initialization" << std::endl;
        }
        return;
    }

    // Check if metrics logging is enabled (opt-in via env var).
    // When disabled, FuzzingSession is a complete no-op: no signal handlers,
    // no atexit, no stderr output, no per-iteration overhead.
    const char* logging_env = std::getenv("SOLFUZZ_METRICS_LOGGING");
    m_logging_enabled = (logging_env && logging_env[0] == '1');
    m_initialized = true;  // Prevent re-entry even when logging is disabled
    if (!m_logging_enabled) {
        return;
    }

    std::cerr << "[FuzzingSession] initialize() called for: " << fuzz_target_name << std::endl;
    std::cerr.flush();  // Ensure message is written immediately

    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] initialize() called for: " << fuzz_target_name << std::endl;
    }

    m_fuzz_target_name = fuzz_target_name;
    m_fuzzer_name = detect_fuzzer_name();
    m_harness_name = "solfuzz";

    std::cerr << "[FuzzingSession] Detected fuzzer: " << m_fuzzer_name << std::endl;
    std::cerr.flush();  // Ensure message is written immediately

    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] Detected fuzzer: " << m_fuzzer_name << std::endl;
    }

    // For libFuzzer and other engines, use normal initialization
    m_session_id = generate_session_id();

    m_target_names = target_names;
    // TODO: m_target_paths
    m_target_paths.clear();
    m_program_id = program_id;
    m_syscall_name = syscall_name;

    // Initialize timing
    m_session_start = std::chrono::steady_clock::now();
    m_last_metrics_time.store(m_session_start);

    // Set up signal handlers
    setup_signal_handlers();

    // Register atexit handler to ensure session end is logged on normal exit
    // IMPORTANT: This ensures session end is always written, even on normal exit
    std::atexit([]() {
        std::cerr << "[FuzzingSession] atexit handler called (pid=" << getpid() << ")" << std::endl;
        std::cerr.flush();
        if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
            std::ofstream dbg(debug_file, std::ios::app);
            dbg << "[FuzzingSession] atexit handler called (pid=" << getpid() << ")" << std::endl;
            dbg.flush();
        }

        if (s_instance) {
            std::cerr << "[FuzzingSession] atexit: s_instance is valid" << std::endl;
            std::cerr.flush();
            // Check shutdown_in_progress to avoid double-logging
            bool should_log = true;
            if (s_shutdown_in_progress.load()) {
                should_log = false;
            }
            if (should_log) {
                std::cerr << "[FuzzingSession] Normal exit detected, logging session end..." << std::endl;
                std::cerr.flush();
                if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
                    std::ofstream dbg(debug_file, std::ios::app);
                    dbg << "[FuzzingSession] Normal exit detected, logging session end..." << std::endl;
                    dbg.flush();
                }
                // CRITICAL: Set m_shutting_down BEFORE calling log_session_end.
                // During atexit, clickhouse-cpp's static objects (TypeAst cache, column factories)
                // may already be destroyed. Setting m_shutting_down causes insert_with_retry_() to
                // skip ClickHouse operations entirely, preventing SEGV crashes.
                MetricsLogger::instance().set_shutting_down(true);

                std::cerr << "[FuzzingSession] About to call log_session_end('completed')..." << std::endl;
                std::cerr.flush();
                s_instance->log_session_end("completed");  // This will skip CH insert due to m_shutting_down
                std::cerr << "[FuzzingSession] log_session_end('completed') returned" << std::endl;
                std::cerr.flush();

                // Wait for queue to drain to ensure session end is written
                try {
                    MetricsLogger::instance().wait_for_queue_drain_();
                    std::cerr << "[FuzzingSession] Queue drained - session end written on normal exit" << std::endl;
                } catch (...) {
                    // Ignore errors, at least session end was enqueued
                    std::cerr << "[FuzzingSession] Session end was enqueued (may be written asynchronously)" << std::endl;
                }
            }
        }
    });

    // Initialize coverage logger
    auto& coverage_logger = MetricsLogger::instance();
    coverage_logger.init(
        m_session_id,
        m_fuzzer_name,
        m_harness_name,
        m_fuzz_target_name,
        m_target_names,
        m_target_paths,
        m_program_id,
        m_syscall_name,
        get_unix_username(),
        get_hostname(),
        getenv_or("FUZZCORP_TASK_ID", ""),
        getenv_or("FUZZCORP_BUNDLE_ID", ""),
        getenv_or("FUZZCORP_ASSET_ID", ""),
        getenv_or("FUZZCORP_ORGANIZATION", ""),
        getenv_or("FUZZCORP_PROJECT", ""),
        getenv_or("FUZZCORP_LINEAGE_NAME", ""),
        getenv_or("FUZZCORP_CORPUS_GROUP", ""),
        getenv_or("FUZZCORP_TASK_TYPE", "")
    );

    // Log session start
    std::cerr << "[FuzzingSession] Logging session start..." << std::endl;
    log_session_start();

    // Mark as initialized to prevent re-initialization (honggfuzz may call LLVMFuzzerInitialize multiple times)
    m_initialized = true;

    std::cerr << "[FuzzingSession] Fuzzing session " << m_session_id << " started with "
              << m_target_names.size() << " targets" << std::endl;
    std::cerr.flush();
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] Fuzzing session " << m_session_id << " started with "
            << m_target_names.size() << " targets" << std::endl;
    }
}

void FuzzingSession::log_execution() {
    if (!m_logging_enabled) return;  // True no-op when SOLFUZZ_METRICS_LOGGING is not set

    // Always aggregate counters; avoid per-execution logging/printing
    // Note: log_execution() is called AFTER the execution completes, so this execution_id
    // corresponds to the execution that just finished

    m_total_executions++;
    uint64_t execution_id = m_total_executions.load();

    // Only perform heavier collection/logging on time-based interval and when logging is enabled
    // Check if at least m_metrics_interval seconds have passed since last metrics log
    auto now = std::chrono::steady_clock::now();

    auto last = m_last_metrics_time.load(std::memory_order_relaxed);
    auto time_since_last_metrics = std::chrono::duration_cast<std::chrono::seconds>(now - last);
    bool should_log_metrics = (time_since_last_metrics >= m_metrics_interval);
    if (should_log_metrics) {
        m_last_metrics_time.store(now, std::memory_order_relaxed);
    }

    if (m_logging_enabled && should_log_metrics) {
        update_memory_peak();
        log_periodic_metrics();
    }
}

void FuzzingSession::log_crash(const std::string& error_msg,
                               const std::string& file,
                               const std::string& function,
                               int line,
                               size_t input_size) {
    if (!m_logging_enabled) {
        return;
    }

    // Increment crash counter
    m_total_crashes++;
    uint64_t crash_count = m_total_crashes.load();
    m_total_input_bytes.fetch_add(input_size);

    // Log bug discovery
    auto& coverage_logger = MetricsLogger::instance();
    coverage_logger.log_bug_discovery(
        "crash_" + std::to_string(crash_count),
        "solfuzz",
        file,
        function,
        line,
        "crash",
        "high",
        "new",
        0, // reproduction_time_ms
        input_size,
        error_msg
    );

    std::cerr << "[FuzzingSession] CRASH: " << error_msg << " (execution #" << m_total_executions.load() << ")" << std::endl;
}

void FuzzingSession::log_hang() {
    if (!m_logging_enabled) {
        return;
    }

    // Increment hang counter
    m_total_hangs++;
    uint64_t hang_count = m_total_hangs.load();
    // Track input size for corpus diversity (use average if available, otherwise estimate)
    uint64_t avg_size = m_total_executions.load() > 0
        ? (m_total_input_bytes.load() / m_total_executions.load())
        : 1024;  // Default 1KB estimate
    m_total_input_bytes.fetch_add(avg_size);

    // Log bug discovery
    auto& coverage_logger = MetricsLogger::instance();
    coverage_logger.log_bug_discovery(
        "hang_" + std::to_string(hang_count),
        "solfuzz",
        __FILE__,
        __FUNCTION__,
        __LINE__,
        "hang",
        "medium",
        "new",
        0, // reproduction_time_ms
        0, // input_size
        "Execution timeout/hang detected"
    );

    std::cerr << "[FuzzingSession] HANG: Execution timeout detected (execution #" << m_total_executions.load() << ")" << std::endl;
}

void FuzzingSession::setup_signal_handlers() {
    // Always install SIGINT/SIGTERM handlers so that metrics
    // are captured on graceful shutdown regardless of ClickHouse.
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);  // This is sent by timeout before SIGKILL

    // SIGABRT is only intercepted when ClickHouse harness-side logging is active.
    // Fuzzer engines (libFuzzer, honggfuzz, AFL) install their own SIGABRT handlers
    // for crash detection and artifact capture.  Overriding them silently breaks
    // crash deduplication and adds latency (ClickHouse I/O + sleeps) to every crash.
    const char* ch_env = std::getenv("SOLFUZZ_HARNESS_CH_ENABLE");
    if (ch_env && ch_env[0] == '1') {
        signal(SIGABRT, signal_handler);
    }
    // Note: SIGKILL (signal 9) cannot be caught, so we must log session end on SIGTERM
}

void FuzzingSession::log_session_start() {
    std::cerr << "[FuzzingSession] log_session_start() called, session_id=" << m_session_id << std::endl;
    std::cerr.flush();
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] log_session_start() called, session_id=" << m_session_id << std::endl;
    }

    // MetricsLogger::init() was already called in initialize(); just log start.
    auto& coverage_logger = MetricsLogger::instance();
    coverage_logger.log_session_start();
}

void FuzzingSession::log_session_end(const std::string& status) {
    std::cerr << "[FuzzingSession] log_session_end() called, status=" << status << ", logging_enabled=" << m_logging_enabled << std::endl;
    std::cerr.flush();
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] log_session_end() called, status=" << status << ", logging_enabled=" << m_logging_enabled << std::endl;
        dbg.flush();  // Ensure message is written to disk immediately
    }

    if (!m_logging_enabled) {
        std::cerr << "[FuzzingSession] log_session_end() skipped (logging disabled)" << std::endl;
        std::cerr.flush();
        if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
            std::ofstream dbg(debug_file, std::ios::app);
            dbg << "[FuzzingSession] log_session_end() skipped (logging disabled)" << std::endl;
            dbg.flush();  // Ensure message is written to disk immediately
        }
        return;
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - m_session_start);
    float cpu_hours = duration.count() / 3600.0f;

    // Get final resource usage
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    uint64_t memory_peak_mb = usage.ru_maxrss / 1024; // Convert KB to MB

    uint64_t total_executions = m_total_executions.load();
    uint64_t total_crashes = m_total_crashes.load();
    uint64_t total_hangs = m_total_hangs.load();
    uint64_t corpus_size = m_corpus_size.load();

    // Write the session end message
    auto& coverage_logger = MetricsLogger::instance();
    coverage_logger.log_session_end(
        status,
        total_executions,
        total_crashes,
        total_hangs,
        cpu_hours,
        memory_peak_mb,
        corpus_size
    );

    // Now do the rest of the work (this can happen after the message is written)
    // Ensure connection is alive before final logging operations
    coverage_logger.ensure_connection();

    float corpus_diversity_score = 0.0f;

    std::cerr << "[FuzzingSession] Session " << m_session_id << " ended. "
              << "Executions: " << total_executions
              << ", Crashes: " << total_crashes
              << ", Hangs: " << total_hangs
              << ", CPU Hours: " << cpu_hours << std::endl;
    std::cerr.flush();
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] Session " << m_session_id << " ended. "
            << "Executions: " << total_executions
            << ", Crashes: " << total_crashes
            << ", Hangs: " << total_hangs
            << ", CPU Hours: " << cpu_hours << std::endl;
    }
}

void FuzzingSession::log_periodic_metrics() {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - m_session_start);
    float cpu_hours = duration.count() / 3600.0f;

    // Get current resource usage
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    // Calculate CPU usage percentage (user + system time / wall time)
    float cpu_usage = 0.0f;
    if (duration.count() > 0) {
        float total_cpu_seconds = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec +
                                   (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000000.0f;
        cpu_usage = (total_cpu_seconds / duration.count()) * 100.0f;
    }
    uint64_t memory_usage_mb = usage.ru_maxrss / 1024; // Convert KB to MB

    float corpus_diversity_score = 0.0f;

    // Calculate execution rates for display
    float executions_per_second = static_cast<float>(m_total_executions.load()) / (duration.count() + 1);
    float crashes_per_second = static_cast<float>(m_total_crashes.load()) / (duration.count() + 1);
    float hangs_per_second = static_cast<float>(m_total_hangs.load()) / (duration.count() + 1);

    auto& coverage_logger = MetricsLogger::instance();
    coverage_logger.log_execution_metrics(
        m_total_executions.load(), // total_executions
        m_total_crashes.load(), // total_crashes
        m_total_hangs.load(), // total_hangs
        cpu_usage,          // cpu_usage (percentage)
        memory_usage_mb,    // memory_usage_mb
        m_corpus_size.load(), // corpus_size
        corpus_diversity_score      // corpus_diversity_score
    );

    std::cerr << "[FuzzingSession] Session " << m_session_id
              << " - Executions: " << m_total_executions.load()
              << ", Crashes: " << m_total_crashes.load()
              << ", Hangs: " << m_total_hangs.load()
              << ", Rate: " << executions_per_second << " exec/s"
              << ", CPU: " << cpu_usage << "%"
              << ", Memory: " << memory_usage_mb << " MB" << std::endl;
}

void FuzzingSession::log_metrics_before_abort() {
    log_metrics_before_abort("", "", -1, "Intentional crash");
}

void FuzzingSession::log_metrics_before_abort(const std::string& file,
                                               const std::string& function,
                                               int line,
                                               const std::string& error_msg) {
    if (!m_logging_enabled) {
        return;
    }

    std::cerr << "[FuzzingSession] Logging latest metrics before intentional crash..." << std::endl;

    // Increment crash counter for this intentional crash
    m_total_crashes++;

    // Log bug discovery with details if we have location information
    if (!file.empty() && !function.empty()) {
        auto& coverage_logger = MetricsLogger::instance();
        // Estimate input size (use average if available, otherwise default)
        uint64_t input_size = m_total_executions.load() > 0
            ? (m_total_input_bytes.load() / m_total_executions.load())
            : 1024;  // Default 1KB estimate

        coverage_logger.log_bug_discovery(
            "verify_crash_" + std::to_string(m_total_crashes.load()),
            "solfuzz",
            file,
            function,
            line,
            "verification_failure",
            "high",
            "new",
            0, // reproduction_time_ms
            input_size,
            error_msg
        );

        std::cerr << "[FuzzingSession] Logged bug discovery: " << error_msg
                  << " at " << file << ":" << line << " in " << function << std::endl;
    }

    // Force log metrics immediately (bypass interval check)
    // This ensures we capture the latest coverage, execution counts, etc. before aborting
    log_periodic_metrics();

    // Also ensure connection is alive before logging
    auto& coverage_logger = MetricsLogger::instance();
    coverage_logger.ensure_connection();

    // Small delay to ensure execution metrics are enqueued
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Log session end before aborting to ensure it's captured
    // Use "crashed" status since this is an intentional crash from verification failure
    // CRITICAL: Log session end first, then try JSON write (JSON write may crash)
    std::cerr << "[FuzzingSession] Logging session end before abort..." << std::endl;
    try {
        log_session_end("crashed");
    } catch (const std::exception& e) {
        std::cerr << "[FuzzingSession] ERROR: Failed to log session end: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[FuzzingSession] ERROR: Failed to log session end (unknown exception)" << std::endl;
    }

    // Small delay to ensure all enqueue operations complete (execution metrics + session end)
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Wait for async logging queue to drain before aborting
    // This ensures ALL events (execution metrics, bug discovery, session end) are written to ClickHouse
    // CRITICAL: Only call wait_for_queue_drain_() ONCE at the end, as it stops the logger thread
    std::cerr << "[FuzzingSession] Waiting for async logging queue to drain..." << std::endl;
    try {
        coverage_logger.wait_for_queue_drain_();
        std::cerr << "[FuzzingSession] Queue drained successfully - all events written" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[FuzzingSession] ERROR during queue drain: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[FuzzingSession] ERROR during queue drain: unknown exception" << std::endl;
    }

    // Mark shutdown as in progress so signal handler won't try to log again
    // This prevents double-logging when abort() triggers SIGABRT
    s_shutdown_in_progress.store(true);

    std::cerr << "[FuzzingSession] All metrics, bug details, and session end logged, aborting..." << std::endl;
}

void FuzzingSession::update_memory_peak() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    uint64_t current_memory = usage.ru_maxrss * 1024; // Convert KB to bytes
    uint64_t current_peak = m_memory_peak.load();
    while (current_memory > current_peak &&
           !m_memory_peak.compare_exchange_weak(current_peak, current_memory)) {
        // Retry if another thread updated it
    }
}

std::string FuzzingSession::generate_session_id() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    std::ostringstream oss;
    oss << getpid() << "_" << timestamp;
    return oss.str();
}

std::string FuzzingSession::detect_fuzzer_name() {
    // Check environment variable first
    char* fuzzer_env = getenv("SOLFUZZ_ENGINE");
    if (fuzzer_env) {
        return std::string(fuzzer_env);
    }

    // Default to libfuzzer for solfuzz
    return "libfuzzer";
}

void FuzzingSession::signal_handler(int sig) {
    std::cerr << "[FuzzingSession] signal_handler called for signal " << sig << " (pid=" << getpid() << ")" << std::endl;
    std::cerr.flush();
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] signal_handler called for signal " << sig << " (pid=" << getpid() << ")" << std::endl;
        dbg.flush();
    }

    // Prevent re-entry: if already shutting down, exit immediately
    bool expected = false;
    if (!s_shutdown_in_progress.compare_exchange_strong(expected, true)) {
        // Already shutting down, force exit
        std::cerr << "[FuzzingSession] Forcing immediate exit (shutdown already in progress)" << std::endl;
        std::cerr.flush();
        if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
            std::ofstream dbg(debug_file, std::ios::app);
            dbg << "[FuzzingSession] Forcing immediate exit (shutdown already in progress)" << std::endl;
            dbg.flush();
        }
        _exit(1);  // Use _exit to avoid cleanup
    }

    // Set up one-shot exit: if user presses CTRL+C again, exit immediately
    signal(SIGINT, SIG_DFL);  // Reset to default handler (will exit immediately on next SIGINT)

    std::cerr << "[FuzzingSession] Signal " << sig << " received, shutting down gracefully..." << std::endl;
    std::cerr.flush();
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] Signal " << sig << " received, shutting down gracefully..." << std::endl;
    }

    if (s_instance) {
        std::cerr << "[FuzzingSession] signal_handler: s_instance is valid" << std::endl;
        std::cerr.flush();
        std::string status = "interrupted";
        if (sig == SIGABRT) {
            status = "crashed";
        }

        try {
            // Force log metrics immediately (bypass interval check) to ensure execution metrics are logged
            // This ensures we capture the latest coverage, execution counts, etc. before exiting
            std::cerr << "[FuzzingSession] Logging execution metrics before exit..." << std::endl;
            try {
                s_instance->log_periodic_metrics();
            } catch (const std::exception& e) {
                std::cerr << "[FuzzingSession] ERROR: Failed to log execution metrics: " << e.what() << std::endl;
            } catch (...) {
                std::cerr << "[FuzzingSession] ERROR: Failed to log execution metrics (unknown exception)" << std::endl;
            }

            // Small delay to ensure execution metrics are enqueued
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // Log session end (this will enqueue coverage events and session end event)
            // IMPORTANT: This must be called to ensure session end is always logged
            // CRITICAL: This must succeed even if JSON write failed
            std::cerr << "[FuzzingSession] Logging session end and coverage data..." << std::endl;
            std::cerr.flush();
            if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
                std::ofstream dbg(debug_file, std::ios::app);
                dbg << "[FuzzingSession] Logging session end and coverage data..." << std::endl;
                dbg.flush();
            }
            std::cerr << "[FuzzingSession] About to call log_session_end('" << status << "')..." << std::endl;
            std::cerr.flush();
            s_instance->log_session_end(status);
            std::cerr << "[FuzzingSession] log_session_end('" << status << "') returned" << std::endl;
            std::cerr.flush();

            // Small delay to ensure all enqueue operations complete (execution metrics + session end)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            // Wait for async logging queue to drain before exiting
            // This ensures ALL events (execution metrics, coverage events, session end) are written to ClickHouse
            // CRITICAL: Only call wait_for_queue_drain_() ONCE at the end, as it stops the logger thread
            std::cerr << "[FuzzingSession] Waiting for async logging queue to drain (ensuring all events are written)..." << std::endl;
            try {
                MetricsLogger::instance().wait_for_queue_drain_();
                std::cerr << "[FuzzingSession] Queue drained successfully - all events written" << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "[FuzzingSession] ERROR during queue drain: " << e.what() << std::endl;
                // Even if queue drain fails, events were at least enqueued
                std::cerr << "[FuzzingSession] Events were enqueued (may be written asynchronously)" << std::endl;
            } catch (...) {
                std::cerr << "[FuzzingSession] ERROR during queue drain: unknown exception" << std::endl;
                // Even if queue drain fails, events were at least enqueued
                std::cerr << "[FuzzingSession] Events were enqueued (may be written asynchronously)" << std::endl;
            }

            // Notify MetricsLogger that we're shutting down (after queue drain)
            try {
                MetricsLogger::instance().set_shutting_down(true);
            } catch (...) { }
        } catch (const std::exception& e) {
            std::cerr << "[FuzzingSession] Error during shutdown logging: " << e.what()
                      << ", exiting anyway" << std::endl;
        } catch (...) {
            std::cerr << "[FuzzingSession] Error during shutdown logging, exiting anyway" << std::endl;
        }
    }

    std::cerr << "[FuzzingSession] Shutdown complete, re-raising signal " << sig << std::endl;
    std::cerr.flush();
    if (const char* debug_file = std::getenv("SOLFUZZ_DEBUG_LOG")) {
        std::ofstream dbg(debug_file, std::ios::app);
        dbg << "[FuzzingSession] Shutdown complete, re-raising signal " << sig << std::endl;
        dbg.flush();
    }

    // Re-raise the original signal with the default handler so the process
    // exit status reflects the real cause of death.  This is the standard
    // POSIX pattern for "clean up then die faithfully":
    //   1. Reset to default handler (SIG_DFL)
    //   2. Re-raise the signal
    // For SIGABRT this produces exit status -6 (Python) / 134 (shell),
    // for SIGTERM it produces -15 / 143, etc.
    // Any external monitor (honggfuzz, subprocess.run, wait()) will see the
    // correct signal-terminated status instead of a clean exit(0).
    signal(sig, SIG_DFL);
    raise(sig);

    // Should never reach here, but just in case:
    _exit(128 + sig);
}

uint64_t FuzzingSession::get_execution_count() const {
    return m_total_executions.load();
}

uint64_t FuzzingSession::get_crash_count() const {
    return m_total_crashes.load();
}

uint64_t FuzzingSession::get_hang_count() const {
    return m_total_hangs.load();
}

} // namespace sol_compat
