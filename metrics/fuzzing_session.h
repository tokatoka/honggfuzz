#pragma once

#include <cstdlib>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <sys/resource.h>

namespace sol_compat {

// Manager handling all logging for a fuzzing session
class FuzzingSession {
public:
    static FuzzingSession& instance();
    
    // Called in LLVMFuzzerInitialize()
    void initialize(const std::string& fuzz_target_name,
                   const std::vector<std::string>& target_names,
                   const std::string& program_id = "",
                   const std::string& syscall_name = "");
    
    // Called in DEFINE_BINARY_PROTO_FUZZER
    void log_execution();
    
    // Called in catch blocks
    void log_crash(const std::string& error_msg, 
                   const std::string& file, 
                   const std::string& function, 
                   int line,
                   size_t input_size);
    
    // Called when detecting hangs
    void log_hang();
    
    const std::string& get_session_id() const { return m_session_id; }
    uint64_t get_execution_count() const;
    uint64_t get_crash_count() const;
    uint64_t get_hang_count() const;
    
    // Log latest metrics before intentional crash (for verify functions)
    void log_metrics_before_abort();
    void log_metrics_before_abort(const std::string& file, 
                                  const std::string& function, 
                                  int line,
                                  const std::string& error_msg = "Verification failure");

private:
    FuzzingSession() = default;
    ~FuzzingSession() = default;
    
    // Session data
    std::string m_session_id;
    std::string m_fuzz_target_name;
    std::string m_fuzzer_name;
    std::string m_harness_name;
    std::vector<std::string> m_target_names;
    std::vector<std::string> m_target_paths;
    std::string m_program_id;
    std::string m_syscall_name;
    
    // Timing
    std::chrono::steady_clock::time_point m_session_start;
    std::atomic<std::chrono::steady_clock::time_point> m_last_metrics_time;
    
    // Counters
    std::atomic<uint64_t> m_total_executions{0};
    std::atomic<uint64_t> m_total_crashes{0};
    std::atomic<uint64_t> m_total_hangs{0};
    std::atomic<uint64_t> m_memory_peak{0};
    std::atomic<uint64_t> m_corpus_size{0};  // Approx. corpus size in bytes
    std::atomic<uint64_t> m_total_input_bytes{0};  // Sum of all input sizes for corpus diversity calculation
    
    // Config
    bool m_logging_enabled{false};
    bool m_initialized{false};  // Guard against multiple initialization (honggfuzz may call LLVMFuzzerInitialize multiple times)
    std::chrono::seconds m_metrics_interval{60}; // Log metrics every 60 seconds (1 minute)

    void setup_signal_handlers();
    void log_session_start();
    void log_session_end(const std::string& status);
    void log_periodic_metrics();
    void update_memory_peak();
    std::string generate_session_id();
    std::string detect_fuzzer_name();
    
    static void signal_handler(int sig);

    static FuzzingSession* s_instance;
};

// Convenience macros for easy integration into fuzzers
// When SOLFUZZ_PARENT_METRICS=1 is set, the honggfuzz parent process handles all metrics logging
// via the hfuzz_metrics_bridge, so harness-side logging is disabled to avoid duplicates.

// Helper to check if parent metrics are enabled (honggfuzz parent handles logging)
inline bool solfuzz_parent_metrics_enabled() {
    static int cached = -1;
    if (cached < 0) {
        const char* val = std::getenv("SOLFUZZ_PARENT_METRICS");
        cached = (val != nullptr && val[0] == '1') ? 1 : 0;
    }
    return cached == 1;
}

#define SOLFUZZ_SESSION_INIT(...) \
    do { \
        if (!sol_compat::solfuzz_parent_metrics_enabled()) { \
            FuzzingSession::instance().initialize(__VA_ARGS__); \
        } \
    } while(0)

#define SOLFUZZ_LOG_EXECUTION() \
    do { \
        if (!sol_compat::solfuzz_parent_metrics_enabled()) { \
            FuzzingSession::instance().log_execution(); \
        } \
    } while(0)

#define SOLFUZZ_LOG_CRASH(error_msg, input_size) \
    do { \
        if (!sol_compat::solfuzz_parent_metrics_enabled()) { \
            FuzzingSession::instance().log_crash(error_msg, __FILE__, __FUNCTION__, __LINE__, input_size); \
        } \
    } while(0)

#define SOLFUZZ_LOG_HANG() \
    do { \
        if (!sol_compat::solfuzz_parent_metrics_enabled()) { \
            FuzzingSession::instance().log_hang(); \
        } \
    } while(0)

// Note: SOLFUZZ_LOG_METRICS_BEFORE_ABORT always runs - crash logging is critical
// and we want it even when parent metrics are enabled (belt and suspenders)
#define SOLFUZZ_LOG_METRICS_BEFORE_ABORT() \
    sol_compat::FuzzingSession::instance().log_metrics_before_abort(__FILE__, __FUNCTION__, __LINE__)

} // namespace sol_compat
