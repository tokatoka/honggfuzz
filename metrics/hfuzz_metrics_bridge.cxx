#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "fuzzing_session.h"
#include "metrics_logger.h"
#include "coverage_symbolizer.h"

// Honggfuzz headers (one directory up from metrics/)
extern "C" {
#include "../libhfcommon/common.h"  // For HF_ATTR_UNUSED
#include "../hfuzz_metrics.h"
}

namespace {

// Debug logging control - set SOLFUZZ_COVERAGE_DEBUG=1 to enable verbose logging
// Default is OFF to reduce log spam and I/O overhead
static bool debug_logging_enabled() {
    static bool enabled = []() {
        const char* env = std::getenv("SOLFUZZ_COVERAGE_DEBUG");
        return env && std::string(env) == "1";
    }();
    return enabled;
}

// Debug log macro - only logs when SOLFUZZ_COVERAGE_DEBUG=1
#define COVERAGE_DEBUG(...) do { \
    if (debug_logging_enabled()) { \
        std::cerr << __VA_ARGS__; \
    } \
} while(0)

// Session state
static std::atomic<bool> s_session_initialized{false};
static std::atomic<uint64_t> s_total_executions{0};
static std::atomic<uint64_t> s_total_crashes{0};
static std::atomic<uint64_t> s_total_hangs{0};
static std::atomic<uint64_t> s_total_input_bytes{0};
static std::atomic<uint64_t> s_coverage_denominator{0};
static std::atomic<uint64_t> s_new_coverage{0};

// Cached coverage values (updated by log_coverage, used by log_execution)
static std::atomic<uint64_t> s_latest_pcs{0};
static std::atomic<uint64_t> s_latest_edges{0};
static std::atomic<uint64_t> s_latest_cmp{0};
static std::atomic<uint64_t> s_latest_corpus_count{0};

static std::chrono::steady_clock::time_point s_session_start;
static std::chrono::steady_clock::time_point s_last_metrics_time;
static std::chrono::steady_clock::time_point s_last_detailed_coverage_time;
static std::string s_target_name;

// PC entry from instrumentation (matches hfuzz_pc_entry_t)
struct PCEntry {
    uintptr_t pc;
    uintptr_t flags;  // 1 = function entry, 0 = basic block

    bool is_function_entry() const { return flags & 1; }
};

// Module tracking for coverage
struct ModuleInfo {
    std::string name;           // Full path to the binary/library
    uint64_t guard_start;       // Widened to 64-bit for future-proofing
    uint64_t guard_count;       // Widened to 64-bit for future-proofing
    uint64_t module_base;       // Module base address (for relative PC calculation)
    std::vector<PCEntry> pc_table;  // RELATIVE PC offsets for symbolization
};
static std::vector<ModuleInfo> s_registered_modules;
static std::mutex s_modules_mutex;

// Time-based metrics interval (log metrics every 60 seconds)
constexpr auto METRICS_INTERVAL = std::chrono::seconds(60);
// Detailed coverage interval (log detailed coverage every 5 minutes)
constexpr auto DETAILED_COVERAGE_INTERVAL = std::chrono::seconds(300);
// Coverage snapshot interval (log per-guard coverage every 60 seconds)
constexpr auto COVERAGE_SNAPSHOT_INTERVAL = std::chrono::seconds(60);

// ============================================================================
// Shared Memory PC Table for cross-process symbolization
// ============================================================================

// Magic number for PC table shared memory: "PCTB"
constexpr uint32_t PC_TABLE_SHM_MAGIC = 0x50435442;
constexpr uint32_t PC_TABLE_SHM_VERSION = 3;  // Bumped for module claim registry
// NOTE: Large Rust libraries like libsolfuzz_agave.so can have 1.5M+ PC entries (24MB+)
// We need enough space for multiple large libraries. 256MB should be sufficient.
constexpr size_t PC_TABLE_SHM_SIZE = 256 * 1024 * 1024;  // 256MB max
constexpr size_t PC_TABLE_MODULE_NAME_SIZE = 256;
constexpr size_t PC_TABLE_MAX_MODULES = 64;

// Module registry entry for tracking registered modules
// NOTE: Must be POD for shared memory - use __atomic_* for thread safety
struct PCTableModuleEntry {
    char module_name[PC_TABLE_MODULE_NAME_SIZE];
    uint64_t pc_count;       // To distinguish different versions of same module
    uint64_t guard_start;    // To distinguish different registrations
};

// Shared memory header (must be POD for atomic operations)
// NOTE: Version bumped to 3 for double-checked locking deduplication fix
struct PCTableShmHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t num_modules;       // Number of registered modules (atomic)
    uint64_t total_entries;     // Total PC entries across all modules (atomic)
    uint64_t data_offset;       // Offset to first module entry data
    uint64_t next_write_offset; // Offset for next module write (atomic)
    uint32_t registration_lock; // Spinlock for module registration (atomic)
    uint32_t reserved_pad;      // Padding for alignment
    uint64_t reserved[1];       // Future use
    // Module registry - tracks which modules have been registered
    // Used for deduplication via double-checked locking pattern
    PCTableModuleEntry module_registry[PC_TABLE_MAX_MODULES];
};

// Module entry in shared memory (fixed size for predictable layout)
struct PCTableShmModule {
    char module_name[PC_TABLE_MODULE_NAME_SIZE];
    uint64_t guard_start;   // Widened to 64-bit for future-proofing
    uint64_t pc_count;      // Widened to 64-bit for future-proofing
    uint64_t module_base;   // Module base address (for relative PC calculation)
    uint64_t reserved;      // Padding for alignment
    // Followed by pc_count * PCTableShmEntry (containing RELATIVE PCs)
};

// PC entry in shared memory
struct PCTableShmEntry {
    uint64_t pc;
    uint64_t flags;
};

// Parent process shared memory state
static void* s_shm_ptr = nullptr;
static size_t s_shm_size = 0;
static std::string s_shm_name;
static int s_shm_fd = -1;

// Flag to track if PC table has been read by parent
static std::atomic<bool> s_pc_table_loaded{false};

/*
 * Read PC table entries from shared memory (parent process).
 * Called periodically by the coverage snapshot thread.
 *
 * The PCs in shared memory are RELATIVE offsets from module base,
 * not absolute runtime addresses. This allows us to use addr2line
 * directly without needing the addresses to be valid in our process.
 */
static bool read_pc_table_from_shm() {
    if (s_pc_table_loaded.load()) {
        return true;  // Already loaded
    }

    // Check if shared memory is mapped
    if (!s_shm_ptr || s_shm_size == 0) {
        std::cerr << "[hfuzz_metrics_bridge] read_pc_table_from_shm: shm not mapped (ptr="
                  << s_shm_ptr << ", size=" << s_shm_size << ")" << std::endl;
        return false;
    }

    PCTableShmHeader* header = static_cast<PCTableShmHeader*>(s_shm_ptr);

    // Verify magic and version
    if (header->magic != PC_TABLE_SHM_MAGIC) {
        std::cerr << "[hfuzz_metrics_bridge] read_pc_table_from_shm: bad magic 0x" << std::hex
                  << header->magic << " (expected 0x" << PC_TABLE_SHM_MAGIC << ")" << std::dec << std::endl;
        return false;  // Not initialized yet
    }

    if (header->version != PC_TABLE_SHM_VERSION) {
        std::cerr << "[hfuzz_metrics_bridge] read_pc_table_from_shm: version mismatch "
                  << header->version << " (expected " << PC_TABLE_SHM_VERSION << ")" << std::endl;
        return false;  // Incompatible version
    }

    uint64_t num_modules = __atomic_load_n(&header->num_modules, __ATOMIC_ACQUIRE);
    uint64_t next_write = __atomic_load_n(&header->next_write_offset, __ATOMIC_ACQUIRE);

    std::cerr << "[hfuzz_metrics_bridge] read_pc_table_from_shm: num_modules=" << num_modules
              << ", next_write=" << next_write << std::endl;

    if (debug_logging_enabled()) {
        FILE* dbg = fopen("/tmp/shm_debug.log", "a");
        if (dbg) {
            fprintf(dbg, "[read_pc_table_from_shm] pid=%d, num_modules=%lu, next_write=%lu, header_size=%lu\n",
                    getpid(), num_modules, (unsigned long)next_write, (unsigned long)sizeof(PCTableShmHeader));
            fclose(dbg);
        }
    }

    if (num_modules == 0) {
        std::cerr << "[hfuzz_metrics_bridge] read_pc_table_from_shm: no modules in shm yet" << std::endl;
        return false;  // No modules yet
    }

    size_t modules_loaded = 0;
    size_t total_pcs = 0;

    // Hold modules mutex while reading and populating
    {
        std::lock_guard<std::mutex> lock(s_modules_mutex);

        // Read all module entries from shared memory
        uint8_t* data_ptr = static_cast<uint8_t*>(s_shm_ptr) + header->data_offset;
        uint8_t* end_ptr = static_cast<uint8_t*>(s_shm_ptr) + s_shm_size;

        for (uint64_t m = 0; m < num_modules && data_ptr < end_ptr; m++) {
            // Read module header
            if (data_ptr + sizeof(PCTableShmModule) > end_ptr) break;
            PCTableShmModule* shm_mod = reinterpret_cast<PCTableShmModule*>(data_ptr);

            // Safety: Ensure module_name is null-terminated within bounds
            // The buffer is PC_TABLE_MODULE_NAME_SIZE (256) bytes, force null-terminate
            shm_mod->module_name[PC_TABLE_MODULE_NAME_SIZE - 1] = '\0';
            std::string module_name(shm_mod->module_name);
            uint64_t guard_start = shm_mod->guard_start;
            uint64_t pc_count = shm_mod->pc_count;
            uint64_t module_base = shm_mod->module_base;

            // Safety: Validate pc_count is reasonable (matches 256M guard count limit)
            if (pc_count > 256 * 1024 * 1024) {
                std::cerr << "[hfuzz_metrics_bridge] WARNING: Suspicious pc_count " << pc_count
                          << " for module " << module_name << ", skipping" << std::endl;
                break;
            }

            // Move past module header
            data_ptr += sizeof(PCTableShmModule);

            // Find or create module entry
            // Match by name AND guard_start to avoid false matches with same ranges
            ModuleInfo* target_module = nullptr;
            for (auto& mod : s_registered_modules) {
                if (mod.name == module_name &&
                    mod.guard_start == guard_start &&
                    mod.guard_count == pc_count) {
                    target_module = &mod;
                    break;
                }
            }

            if (!target_module) {
                ModuleInfo info;
                info.name = module_name;
                info.guard_start = guard_start;
                info.guard_count = pc_count;
                info.module_base = module_base;
                s_registered_modules.push_back(std::move(info));
                target_module = &s_registered_modules.back();
            } else {
                target_module->module_base = module_base;
            }

            // Read PC entries (these are RELATIVE offsets from module base)
            target_module->pc_table.clear();
            target_module->pc_table.reserve(pc_count);

            size_t entries_size = pc_count * sizeof(PCTableShmEntry);
            if (data_ptr + entries_size > end_ptr) break;

            PCTableShmEntry* entries = reinterpret_cast<PCTableShmEntry*>(data_ptr);
            for (uint64_t i = 0; i < pc_count; i++) {
                PCEntry entry;
                entry.pc = entries[i].pc;  // Already relative offset
                entry.flags = entries[i].flags;
                target_module->pc_table.push_back(entry);
            }

            // Move past PC entries
            data_ptr += entries_size;

            modules_loaded++;
            total_pcs += pc_count;
        }
    }  // Release modules mutex here

    if (modules_loaded > 0) {
        s_pc_table_loaded.store(true);
        std::cerr << "[hfuzz_metrics_bridge] Loaded PC table from shared memory: "
                  << modules_loaded << " modules, " << total_pcs << " PCs" << std::endl;

        // Debug: log each module loaded
        {
            std::lock_guard<std::mutex> lock(s_modules_mutex);
            for (const auto& mod : s_registered_modules) {
                std::cerr << "[hfuzz_metrics_bridge]   Module: " << mod.name
                          << " (guard_start=" << mod.guard_start
                          << ", count=" << mod.guard_count
                          << ", base=0x" << std::hex << mod.module_base << std::dec
                          << ", pc_table_size=" << mod.pc_table.size() << ")" << std::endl;
                // Print a sample of PC values
                if (!mod.pc_table.empty()) {
                    std::cerr << "[hfuzz_metrics_bridge]     First 3 PCs (relative): ";
                    for (size_t i = 0; i < std::min<size_t>(3, mod.pc_table.size()); i++) {
                        std::cerr << "0x" << std::hex << mod.pc_table[i].pc << std::dec << " ";
                    }
                    std::cerr << std::endl;
                }
            }
        }

        // NOTE: We NO LONGER pre-symbolize all PCs here.
        // Pre-symbolizing millions of PCs (e.g., 3M from libsolfuzz_agave.so) is too slow.
        // Instead, we only symbolize on-demand in symbolize_guards() for covered guards.
        auto& symbolizer = sol_compat::CoverageSymbolizer::instance();
        symbolizer.init_module_filter();

        std::cerr << "[hfuzz_metrics_bridge] PC table loaded (symbolization is on-demand)" << std::endl;
        return true;
    }

    return false;
}

// Forward declaration for symbolization helper
static std::string symbolize_pc(uintptr_t pc);

// ============================================================================
// Background Coverage Snapshot Thread Infrastructure
// ============================================================================

// Symbolized guard information cache
struct SymbolizedGuard {
    std::string file_path;
    std::string function_name;
    std::string module_name;
    uint64_t line_number;       // Widened to 64-bit for consistency
    bool is_function_entry;
};

// Background coverage snapshot thread state
static std::thread s_coverage_thread;
static std::atomic<bool> s_coverage_thread_running{false};
static std::mutex s_coverage_thread_mutex;
static std::condition_variable s_coverage_thread_cv;

// Previous coverage snapshot for incremental diff
static std::vector<uint8_t> s_prev_coverage_snapshot;
static std::mutex s_snapshot_mutex;

// Guard-to-symbol cache (populated incrementally, persists for session)
// Key is guard ID (64-bit for future-proofing)
static std::unordered_map<uint64_t, SymbolizedGuard> s_guard_symbol_cache;
static std::mutex s_symbol_cache_mutex;

// Pointer to the shared feedback structure (set during session init)
static const uint8_t* s_coverage_feedback_map = nullptr;
static std::atomic<uint64_t>* s_guard_count_ptr = nullptr;

// Get PC address for a given guard ID using registered modules
static uintptr_t get_pc_for_guard(uint64_t guard_id) {
    std::lock_guard<std::mutex> lock(s_modules_mutex);
    for (const auto& mod : s_registered_modules) {
        if (guard_id >= mod.guard_start &&
            guard_id < mod.guard_start + mod.guard_count) {
            size_t idx = guard_id - mod.guard_start;
            if (idx < mod.pc_table.size()) {
                return mod.pc_table[idx].pc;
            }
        }
    }
    return 0;
}

// Get module name for a given guard ID
static std::string get_module_for_guard(uint64_t guard_id) {
    std::lock_guard<std::mutex> lock(s_modules_mutex);
    for (const auto& mod : s_registered_modules) {
        if (guard_id >= mod.guard_start &&
            guard_id < mod.guard_start + mod.guard_count) {
            return mod.name;
        }
    }
    return "unknown";
}

// Get module-relative guard index for a given absolute guard ID
// This is used to match with the PC Guard Registry which uses 0-based enumeration per module
static uint64_t get_module_relative_guard_id(uint64_t guard_id) {
    std::lock_guard<std::mutex> lock(s_modules_mutex);
    for (const auto& mod : s_registered_modules) {
        if (guard_id >= mod.guard_start &&
            guard_id < mod.guard_start + mod.guard_count) {
            return guard_id - mod.guard_start;
        }
    }
    return guard_id;  // Fallback: return as-is if module not found
}

// Check if guard is a function entry point
// NOTE: Caller must hold s_modules_mutex OR pass already_locked=true
static bool is_guard_function_entry_unlocked(uint64_t guard_id) {
    // Must be called with s_modules_mutex already held
    for (const auto& mod : s_registered_modules) {
        if (guard_id >= mod.guard_start &&
            guard_id < mod.guard_start + mod.guard_count) {
            size_t idx = guard_id - mod.guard_start;
            if (idx < mod.pc_table.size()) {
                return mod.pc_table[idx].is_function_entry();
            }
        }
    }
    return false;
}

static bool is_guard_function_entry(uint64_t guard_id) {
    std::lock_guard<std::mutex> lock(s_modules_mutex);
    return is_guard_function_entry_unlocked(guard_id);
}

// Symbolize a batch of guards and populate the cache
// NOTE: pc_table contains RELATIVE PCs (offset from module base), not runtime addresses.
// Symbolization uses pre-cached results from read_pc_table_from_shm().
static void symbolize_guards(const std::vector<uint64_t>& guards) {
    COVERAGE_DEBUG("[hfuzz_metrics_bridge] symbolize_guards called with " << guards.size() << " guards" << std::endl);
    if (guards.empty()) return;

    // Debug: show first few guard IDs
    if (debug_logging_enabled() && !guards.empty()) {
        std::cerr << "[hfuzz_metrics_bridge]   First guards: ";
        for (size_t i = 0; i < std::min<size_t>(5, guards.size()); i++) {
            std::cerr << guards[i] << " ";
        }
        std::cerr << std::endl;
    }

    auto& symbolizer = sol_compat::CoverageSymbolizer::instance();

    // Collect guards that need symbolization, grouped by module
    std::unordered_map<std::string, std::vector<std::pair<uint64_t, uintptr_t>>> module_guards;
    std::vector<uint64_t> guards_to_resolve;

    {
        std::lock_guard<std::mutex> lock(s_symbol_cache_mutex);
        std::lock_guard<std::mutex> mod_lock(s_modules_mutex);

        COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Registered modules: " << s_registered_modules.size() << std::endl);
        if (debug_logging_enabled()) {
            for (const auto& mod : s_registered_modules) {
                std::cerr << "[hfuzz_metrics_bridge]   Module " << mod.name
                          << " guard_start=" << mod.guard_start
                          << " count=" << mod.guard_count
                          << " pc_table_size=" << mod.pc_table.size() << std::endl;
            }
        }

        for (uint64_t guard : guards) {
            if (s_guard_symbol_cache.find(guard) != s_guard_symbol_cache.end()) {
                continue;  // Already cached
            }

            // Find the module and relative PC for this guard
            // NOTE: Only consider modules with a non-empty pc_table (those with actual PC data)
            // This avoids matching against modules like libhfuzz_metrics_bridge.so which are
            // instrumented but whose PC table isn't available in shared memory.
            bool found = false;
            for (const auto& mod : s_registered_modules) {
                // Skip modules without PC table data
                if (mod.pc_table.empty()) continue;

                if (guard >= mod.guard_start &&
                    guard < mod.guard_start + mod.guard_count) {
                    size_t idx = guard - mod.guard_start;
                    if (idx < mod.pc_table.size()) {
                        uintptr_t rel_pc = mod.pc_table[idx].pc;
                        if (rel_pc != 0) {
                            module_guards[mod.name].push_back({guard, rel_pc});
                            guards_to_resolve.push_back(guard);
                        }
                    }
                    found = true;
                    break;
                }
            }
            if (!found) {
                static int not_found_count = 0;
                if (not_found_count++ < 5) {
                    std::cerr << "[hfuzz_metrics_bridge]   Guard " << guard << " not found in any module" << std::endl;
                }
            }
        }
    }

    COVERAGE_DEBUG("[hfuzz_metrics_bridge]   guards_to_resolve: " << guards_to_resolve.size() << std::endl);

    if (guards_to_resolve.empty()) return;

    // For each module, ensure symbols are resolved and populate guard cache
    COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Checking " << module_guards.size() << " modules for symbolization" << std::endl);
    for (const auto& kv : module_guards) {
        const std::string& module_path = kv.first;
        const auto& guard_pc_pairs = kv.second;

        COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Checking module " << module_path << " with " << guard_pc_pairs.size() << " guards" << std::endl);

        // Collect any PCs not yet in symbolizer cache
        std::vector<std::pair<uintptr_t, uintptr_t>> pcs_to_resolve;
        for (const auto& gp : guard_pc_pairs) {
            uintptr_t rel_pc = gp.second;
            sol_compat::PcLocation loc;
            if (!symbolizer.get_pc_location_for_module(module_path, rel_pc, loc)) {
                pcs_to_resolve.push_back({rel_pc, 0});  // flags=0 for now
            }
        }

        COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Need to resolve " << pcs_to_resolve.size() << " new PCs" << std::endl);

        // Batch resolve any missing symbols
        if (!pcs_to_resolve.empty()) {
            COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Calling batch_resolve_for_module..." << std::endl);
            symbolizer.batch_resolve_for_module(module_path, pcs_to_resolve);
            COVERAGE_DEBUG("[hfuzz_metrics_bridge]   batch_resolve_for_module completed" << std::endl);
        }
    }

    COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Populating guard symbol cache..." << std::endl);

    // Populate guard symbol cache
    COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Acquiring locks..." << std::endl);
    {
        std::lock_guard<std::mutex> lock(s_symbol_cache_mutex);
        std::lock_guard<std::mutex> mod_lock(s_modules_mutex);

        COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Got locks, populating " << module_guards.size() << " modules" << std::endl);

        for (const auto& kv : module_guards) {
            const std::string& module_path = kv.first;
            const auto& guard_pc_pairs = kv.second;

            COVERAGE_DEBUG("[hfuzz_metrics_bridge]   Processing module " << module_path << " (" << guard_pc_pairs.size() << " guards)" << std::endl);

            for (const auto& gp : guard_pc_pairs) {
                uint64_t guard = gp.first;
                uintptr_t rel_pc = gp.second;

                SymbolizedGuard sym;
                sym.module_name = module_path;
                // Use unlocked version since we already hold s_modules_mutex
                sym.is_function_entry = is_guard_function_entry_unlocked(guard);

                // Get location info from symbolizer (keyed by relative PC)
                sol_compat::PcLocation loc;
                if (symbolizer.get_pc_location_for_module(module_path, rel_pc, loc) && !loc.frames.empty()) {
                    const auto& frame = loc.frames[0];  // Use outermost frame
                    sym.file_path = frame.file;
                    sym.function_name = frame.func;
                    sym.line_number = frame.line;
                } else {
                    // Fallback - use hex address
                    std::ostringstream oss;
                    oss << "0x" << std::hex << rel_pc;
                    sym.function_name = oss.str();
                    sym.file_path = module_path;
                    sym.line_number = 0;
                }

                s_guard_symbol_cache[guard] = std::move(sym);
            }
        }
    }

    COVERAGE_DEBUG("[hfuzz_metrics_bridge] Symbolized " << guards_to_resolve.size()
              << " new guards (cache size: " << s_guard_symbol_cache.size() << ")" << std::endl);

    // Debug: show first cached guard (only when debug enabled)
    if (debug_logging_enabled() && !s_guard_symbol_cache.empty()) {
        auto it = s_guard_symbol_cache.begin();
        std::cerr << "[hfuzz_metrics_bridge]   First cached: guard " << it->first
                  << " -> " << it->second.function_name << " @ " << it->second.file_path
                  << ":" << it->second.line_number << std::endl;
    }
}

// Log ONLY newly covered guards to ClickHouse (event-sourced approach)
//
// This is the efficient approach: instead of logging ALL covered guards every 10 seconds
// (which creates ~1.7M rows per snapshot), we only log NEWLY covered guards.
// Combined with the PC Guard Registry, this allows reconstruction of full coverage state
// at any point in time via: "SELECT * FROM coverage_guard_first_hits WHERE first_hit_time <= T"
//
// IMPORTANT: We log MODULE-RELATIVE guard_id, not absolute guard_id.
// The PC Guard Registry uses 0-based enumeration per module.
//
static void log_first_hits_to_clickhouse(const std::vector<uint64_t>& newly_covered_guards) {

    COVERAGE_DEBUG("[hfuzz_metrics_bridge] log_first_hits_to_clickhouse called with "
              << newly_covered_guards.size() << " newly covered guards" << std::endl);

    if (newly_covered_guards.empty()) return;

    try {
        auto& logger = sol_compat::MetricsLogger::instance();

        // Build guard first-hit entries for batch insert
        std::vector<sol_compat::MetricsLogger::GuardFirstHitEntry> entries;
        entries.reserve(newly_covered_guards.size());

        size_t symbolized_count = 0;
        size_t unsymbolized_count = 0;
        {
            std::lock_guard<std::mutex> lock(s_symbol_cache_mutex);
            COVERAGE_DEBUG("[hfuzz_metrics_bridge] Building first-hit entries (cache size: "
                      << s_guard_symbol_cache.size() << ")" << std::endl);

            for (const uint64_t guard_id : newly_covered_guards) {
                sol_compat::MetricsLogger::GuardFirstHitEntry entry;
                // Use module-relative guard_id to match PC Guard Registry (which uses 0-based per-module)
                entry.guard_id = get_module_relative_guard_id(guard_id);

                // Symbol cache is keyed by absolute guard_id
                auto it = s_guard_symbol_cache.find(guard_id);
                if (it != s_guard_symbol_cache.end()) {
                    // Use cached symbol info
                    const auto& sym = it->second;
                    entry.file_path = sym.file_path;
                    entry.function_name = sym.function_name;
                    entry.line_number = sym.line_number;
                    entry.module_name = sym.module_name;
                    entry.coverage_type = sym.is_function_entry ? "function" : "block";
                    symbolized_count++;
                } else {
                    // Fallback: log guard with minimal info (symbolization happens in dashboard)
                    std::ostringstream oss;
                    oss << "guard_" << entry.guard_id;  // Use module-relative ID
                    entry.function_name = oss.str();
                    entry.file_path = "unknown";
                    entry.line_number = entry.guard_id;  // Use module-relative ID for ordering
                    entry.module_name = s_target_name;
                    entry.coverage_type = "block";
                    unsymbolized_count++;
                }

                entries.push_back(std::move(entry));
            }

            COVERAGE_DEBUG("[hfuzz_metrics_bridge] Built " << entries.size() << " first-hit entries: "
                      << symbolized_count << " symbolized, " << unsymbolized_count << " unsymbolized" << std::endl);
        }

        if (!entries.empty()) {
            logger.log_guard_first_hits(entries);
            COVERAGE_DEBUG("[hfuzz_metrics_bridge] Logged " << entries.size()
                      << " guard first-hit events to ClickHouse" << std::endl);
        }
    } catch (const std::exception& e) {
        std::cerr << "[hfuzz_metrics_bridge] Error logging first-hits: "
                  << e.what() << std::endl;
    }
}

// Background thread function for periodic coverage snapshots
static void coverage_snapshot_thread_func() {
    COVERAGE_DEBUG("[hfuzz_metrics_bridge] Coverage snapshot thread started" << std::endl);

    while (s_coverage_thread_running.load()) {
        // Wait for interval or shutdown signal (shorter wait on first iteration)
        static bool first_iteration = true;
        auto wait_time = first_iteration ? std::chrono::seconds(1) : COVERAGE_SNAPSHOT_INTERVAL;
        first_iteration = false;

        {
            std::unique_lock<std::mutex> lock(s_coverage_thread_mutex);
            s_coverage_thread_cv.wait_for(lock, wait_time, []() {
                return !s_coverage_thread_running.load();
            });
        }

        if (!s_coverage_thread_running.load()) break;
        if (!s_coverage_feedback_map || !s_guard_count_ptr) continue;

        // Get current guard count
        uint64_t guard_count_raw = s_guard_count_ptr->load(std::memory_order_relaxed);

        // Safety checks: ensure guard_count is sane
        // - Must be > 0 (otherwise no guards to check)
        // - Must be <= 256M (sanity limit to prevent memory exhaustion)
        // - Must fit in size_t for vector operations
        if (guard_count_raw == 0 || guard_count_raw > 256 * 1024 * 1024) continue;

        // Safe cast after bounds check
        const size_t guard_count = static_cast<size_t>(guard_count_raw);

        std::vector<uint64_t> newly_covered;
        std::vector<std::pair<uint64_t, uint8_t>> all_covered;

        {
            std::lock_guard<std::mutex> lock(s_snapshot_mutex);

            // Ensure snapshot buffer is large enough
            // Use try/catch to handle allocation failure gracefully
            try {
                if (s_prev_coverage_snapshot.size() < guard_count) {
                    s_prev_coverage_snapshot.resize(guard_count, 0);
                }
            } catch (const std::bad_alloc& e) {
                std::cerr << "[hfuzz_metrics_bridge] ERROR: Failed to allocate snapshot buffer for "
                          << guard_count << " guards: " << e.what() << std::endl;
                continue;  // Skip this snapshot, try again next time
            }

            // Scan for coverage changes
            // NOTE: Guard 0 is reserved/unused in honggfuzz, so we start at 1
            for (size_t i = 1; i < guard_count; i++) {
                uint8_t current = s_coverage_feedback_map[i];
                uint8_t prev = s_prev_coverage_snapshot[i];

                if (current > 0) {
                    all_covered.emplace_back(static_cast<uint64_t>(i), current);

                    if (prev == 0) {
                        newly_covered.push_back(static_cast<uint64_t>(i));
                    }
                }

                s_prev_coverage_snapshot[i] = current;
            }
        }

        // Log stats (only when debug enabled to reduce spam)
        COVERAGE_DEBUG("[hfuzz_metrics_bridge] Coverage snapshot: "
                  << all_covered.size() << " total covered, "
                  << newly_covered.size() << " newly covered" << std::endl);

        // Try to load PC table from shared memory (written by child processes)
        // This is idempotent - only loads once
        if (!s_pc_table_loaded.load()) {
            read_pc_table_from_shm();
        }

        // Symbolize newly covered guards (incremental)
        if (!newly_covered.empty()) {
            symbolize_guards(newly_covered);
        }

        // Log ONLY newly covered guards to ClickHouse (event-sourced approach)
        // This replaces the old approach of logging ALL covered guards every snapshot,
        // reducing data volume by 99.9%+ (from ~1.7M rows to ~0-1000 rows per snapshot)
        if (!newly_covered.empty()) {
            log_first_hits_to_clickhouse(newly_covered);
        }
    }

    COVERAGE_DEBUG("[hfuzz_metrics_bridge] Coverage snapshot thread stopped" << std::endl);
}

// Start the background coverage snapshot thread
static void start_coverage_snapshot_thread(const uint8_t* guard_map,
                                           std::atomic<uint64_t>* guard_count) {
    if (s_coverage_thread_running.load()) return;

    s_coverage_feedback_map = guard_map;
    s_guard_count_ptr = guard_count;

    s_coverage_thread_running.store(true);
    s_coverage_thread = std::thread(coverage_snapshot_thread_func);

    COVERAGE_DEBUG("[hfuzz_metrics_bridge] Started coverage snapshot thread" << std::endl);
}

// Stop the background coverage snapshot thread
static void stop_coverage_snapshot_thread() {
    if (!s_coverage_thread_running.load()) return;

    s_coverage_thread_running.store(false);
    s_coverage_thread_cv.notify_all();

    if (s_coverage_thread.joinable()) {
        s_coverage_thread.join();
    }

    std::cerr << "[hfuzz_metrics_bridge] Stopped coverage snapshot thread" << std::endl;
}

} // anonymous namespace

extern "C" {

/*
 * Initialize metrics session at fuzzer startup.
 * Called from honggfuzz main() after threads are started.
 *
 * This runs in the honggfuzz PARENT process, so we initialize MetricsLogger
 * directly here (the harness child processes have their own FuzzingSession).
 */
void hfuzz_metrics_bridge_session_init(const char* target_name,
                                 int argc HF_ATTR_UNUSED,
                                 char** argv HF_ATTR_UNUSED) {
    if (s_session_initialized.exchange(true)) {
        // Already initialized
        return;
    }

    s_target_name = target_name ? target_name : "honggfuzz";
    s_session_start = std::chrono::steady_clock::now();
    s_last_metrics_time = s_session_start;

    std::cerr << "[hfuzz_metrics_bridge] Initializing honggfuzz parent metrics for target: "
              << s_target_name << std::endl;

    // Create shared memory for PC table (used by child processes to report PC data)
    {
        // Generate unique shm name based on PID
        s_shm_name = "/solfuzz_pc_table_" + std::to_string(getpid());

        // Create shared memory
        s_shm_fd = shm_open(s_shm_name.c_str(), O_CREAT | O_RDWR, 0644);
        if (s_shm_fd >= 0) {
            // Set size
            if (ftruncate(s_shm_fd, PC_TABLE_SHM_SIZE) == 0) {
                // Map the memory
                s_shm_ptr = mmap(nullptr, PC_TABLE_SHM_SIZE, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, s_shm_fd, 0);
                if (s_shm_ptr != MAP_FAILED) {
                    s_shm_size = PC_TABLE_SHM_SIZE;

                    // Initialize header
                    PCTableShmHeader* header = static_cast<PCTableShmHeader*>(s_shm_ptr);
                    memset(header, 0, sizeof(PCTableShmHeader));  // Clear everything including registry
                    header->magic = PC_TABLE_SHM_MAGIC;
                    header->version = PC_TABLE_SHM_VERSION;
                    header->num_modules = 0;
                    header->total_entries = 0;
                    header->data_offset = sizeof(PCTableShmHeader);
                    header->next_write_offset = sizeof(PCTableShmHeader);
                    header->registration_lock = 0;  // Spinlock unlocked
                    // module_registry[] already zeroed by memset

                    // Set environment variable for children to find the shm
                    setenv("SOLFUZZ_PC_TABLE_SHM", s_shm_name.c_str(), 1);

                    std::cerr << "[hfuzz_metrics_bridge] Created PC table shared memory: "
                              << s_shm_name << " (" << PC_TABLE_SHM_SIZE / 1024 / 1024 << " MB)" << std::endl;
                } else {
                    int err = errno;
                    std::cerr << "[hfuzz_metrics_bridge] ERROR: mmap failed for shared memory: "
                              << strerror(err) << " (errno=" << err << ")" << std::endl;
                    s_shm_ptr = nullptr;
                    close(s_shm_fd);
                    s_shm_fd = -1;
                    shm_unlink(s_shm_name.c_str());
                }
            } else {
                int err = errno;
                std::cerr << "[hfuzz_metrics_bridge] ERROR: ftruncate failed for shared memory (size="
                          << PC_TABLE_SHM_SIZE << "): " << strerror(err) << " (errno=" << err << ")" << std::endl;
                close(s_shm_fd);
                s_shm_fd = -1;
                shm_unlink(s_shm_name.c_str());
            }
        } else {
            int err = errno;
            std::cerr << "[hfuzz_metrics_bridge] ERROR: shm_open failed for '" << s_shm_name
                      << "': " << strerror(err) << " (errno=" << err << ")" << std::endl;
        }
    }

    // Register atexit handler to protect against crashes during static destruction.
    // If the process exits without calling hfuzz_metrics_bridge_session_end() (e.g., via
    // exit() or crash), the background logger thread may still be running. When static
    // destructors run, clickhouse-cpp's statics (TypeAst cache) may be destroyed before
    // the thread finishes, causing SEGV. Setting m_shutting_down causes the thread to
    // skip ClickHouse operations and exit cleanly.
    static bool atexit_registered = false;
    if (!atexit_registered) {
        atexit_registered = true;
        std::atexit([]() {
            if (s_session_initialized.load()) {
                std::cerr << "[hfuzz_metrics_bridge] atexit: setting shutdown flag to prevent CH crashes" << std::endl;

                // Stop the coverage snapshot thread FIRST to prevent it from accessing CH
                // while we're shutting down. This is important because the thread uses
                // MetricsLogger::instance() which may be destroyed during atexit.
                stop_coverage_snapshot_thread();

                // Set shutdown flag - this causes insert_with_retry_ to skip CH ops
                sol_compat::MetricsLogger::instance().set_shutting_down(true);
                // Note: We don't call wait_for_queue_drain_() here because we want to
                // exit quickly and avoid blocking. The shutdown flag prevents crashes.

                // Cleanup shared memory
                if (s_shm_ptr && s_shm_ptr != MAP_FAILED) {
                    munmap(s_shm_ptr, s_shm_size);
                    s_shm_ptr = nullptr;
                }
                if (!s_shm_name.empty()) {
                    shm_unlink(s_shm_name.c_str());
                }
            }
        });
    }

    // Initialize MetricsLogger directly for the parent process
    // This is separate from FuzzingSession which runs in child processes
    try {
        // The metrics bridge runs in the honggfuzz PARENT process.
        // MetricsLogger::init() checks SOLFUZZ_HARNESS_CH_ENABLE to decide if CH is enabled.
        // For the parent process, we should enable CH based on SOLFUZZ_CH_ENABLE.
        // Set SOLFUZZ_HARNESS_CH_ENABLE=1 if SOLFUZZ_CH_ENABLE=1 to enable CH logging.
        const char* ch_enable = std::getenv("SOLFUZZ_CH_ENABLE");
        if (ch_enable && std::string(ch_enable) == "1") {
            setenv("SOLFUZZ_HARNESS_CH_ENABLE", "1", 1);
            std::cerr << "[hfuzz_metrics_bridge] Enabling ClickHouse metrics (SOLFUZZ_CH_ENABLE=1)" << std::endl;
        }

        auto& logger = sol_compat::MetricsLogger::instance();

        // Generate a session ID for the parent process
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
        std::string session_id = std::to_string(getpid()) + "_" + std::to_string(timestamp);

        // Get hostname and username
        char hostname[256] = "unknown";
        gethostname(hostname, sizeof(hostname));

        const char* user = std::getenv("USER");
        if (!user) user = "unknown";

        // Get env vars for task context
        auto getenv_or = [](const char* name, const char* def) -> std::string {
            const char* val = std::getenv(name);
            return val ? val : def;
        };

        // Initialize with full context
        logger.init(
            session_id,                                    // session_id
            "honggfuzz",                                   // fuzzer_name
            "hfuzz_metrics_bridge",                        // harness_name
            s_target_name,                                 // fuzz_target
            {},                                            // target_names
            {},                                            // target_paths
            getenv_or("SOLFUZZ_PROGRAM_ID", ""),           // program_id
            "",                                            // syscall_name
            user,                                          // user_name
            hostname,                                      // host_name
            getenv_or("FUZZCORP_TASK_ID", ""),             // task_id
            getenv_or("FUZZCORP_BUNDLE_ID", ""),           // bundle_id
            getenv_or("FUZZCORP_ASSET_ID", ""),            // asset_id
            getenv_or("FUZZCORP_ORGANIZATION", ""),        // organization
            getenv_or("FUZZCORP_PROJECT", ""),             // project
            getenv_or("FUZZCORP_LINEAGE_NAME", ""),        // lineage_name
            getenv_or("FUZZCORP_CORPUS_GROUP", ""),        // corpus_group
            getenv_or("FUZZCORP_TASK_TYPE", "")            // task_type
        );

        // Log session start event
        logger.log_session_start();

        std::cerr << "[hfuzz_metrics_bridge] MetricsLogger initialized with session "
                  << session_id << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[hfuzz_metrics_bridge] Warning: Failed to initialize MetricsLogger: "
                  << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[hfuzz_metrics_bridge] Warning: MetricsLogger initialization failed"
                  << std::endl;
    }
}

/*
 * Finalize metrics session at fuzzer shutdown.
 * Called from honggfuzz main() after mainThreadLoop() returns.
 */
void hfuzz_metrics_bridge_session_end(const char* status,
                                uint64_t executions,
                                uint64_t crashes,
                                uint64_t hangs,
                                uint64_t cpu_seconds,
                                uint64_t memory_peak_mb) {
    if (!s_session_initialized.load()) {
        return;
    }

    std::cerr << "[hfuzz_metrics_bridge] Session ending - status: " << status
              << ", executions: " << executions
              << ", crashes: " << crashes
              << ", hangs: " << hangs
              << ", cpu_seconds: " << cpu_seconds
              << ", memory_peak_mb: " << memory_peak_mb << std::endl;

    // Stop coverage snapshot thread first
    stop_coverage_snapshot_thread();

    try {
        auto& logger = sol_compat::MetricsLogger::instance();
        float cpu_hours = static_cast<float>(cpu_seconds) / 3600.0f;

        uint64_t corpus_size = s_total_input_bytes.load();

        logger.log_session_end(
            status ? status : "completed",
            executions,
            crashes,
            hangs,
            cpu_hours,
            memory_peak_mb,
            corpus_size
        );

        // Wait for queue to drain
        logger.wait_for_queue_drain_();
    } catch (const std::exception& e) {
        std::cerr << "[hfuzz_metrics_bridge] Error logging session end: "
                  << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[hfuzz_metrics_bridge] Unknown error logging session end"
                  << std::endl;
    }

    // Cleanup shared memory
    if (s_shm_ptr && s_shm_ptr != MAP_FAILED) {
        munmap(s_shm_ptr, s_shm_size);
        s_shm_ptr = nullptr;
        s_shm_size = 0;
    }
    if (s_shm_fd >= 0) {
        close(s_shm_fd);
        s_shm_fd = -1;
    }
    if (!s_shm_name.empty()) {
        shm_unlink(s_shm_name.c_str());
        std::cerr << "[hfuzz_metrics_bridge] Cleaned up shared memory: " << s_shm_name << std::endl;
        s_shm_name.clear();
    }

    s_session_initialized.store(false);
}

/*
 * Register the shared coverage feedback pointers for background monitoring.
 * This starts the background coverage snapshot thread.
 *
 * @param guard_map Pointer to the pcGuardMap (8-bit counters per guard)
 * @param guard_count Pointer to the atomic guard count
 */
void hfuzz_metrics_bridge_register_coverage_feedback(const uint8_t* guard_map,
                                                      void* guard_count_ptr) {
    if (!s_session_initialized.load()) {
        return;
    }

    if (!guard_map || !guard_count_ptr) {
        std::cerr << "[hfuzz_metrics_bridge] Warning: register_coverage_feedback called with null pointers" << std::endl;
        return;
    }

    std::cerr << "[hfuzz_metrics_bridge] Registering coverage feedback pointers" << std::endl;

    // Start the background coverage snapshot thread
    start_coverage_snapshot_thread(guard_map, reinterpret_cast<std::atomic<uint64_t>*>(guard_count_ptr));
}

/*
 * Log a single execution completion.
 * Uses time-based batching to avoid per-execution overhead.
 *
 * This is called from the honggfuzz PARENT process after each execution.
 */
void hfuzz_metrics_bridge_log_execution(size_t input_size,
                                  uint64_t exec_time_us) {
    if (!s_session_initialized.load()) {
        return;
    }

    // Increment local counters
    uint64_t exec_count = s_total_executions.fetch_add(1, std::memory_order_relaxed) + 1;
    s_total_input_bytes.fetch_add(input_size, std::memory_order_relaxed);

    // NOTE: We no longer call log_execution_metrics here because:
    // 1. log_fuzzer_stats is called every 150s from input.c with complete stats
    // 2. log_execution_metrics creates events with zeros for all stats fields
    //    (sched, decay, health, diff-fuzz), which pollutes the timeseries data
    // 3. The zero-valued events cause "nose dive" artifacts on dashboard charts
    //
    // All execution and stats data is now logged via hfuzz_metrics_log_stats().
}

/*
 * Log a crash detection.
 */
void hfuzz_metrics_bridge_log_crash(const char* description,
                              uint64_t backtrace_hash,
                              size_t input_size) {
    if (!s_session_initialized.load()) {
        return;
    }

    s_total_crashes.fetch_add(1, std::memory_order_relaxed);
    s_total_input_bytes.fetch_add(input_size, std::memory_order_relaxed);

    std::cerr << "[hfuzz_metrics_bridge] Crash detected - hash: 0x"
              << std::hex << backtrace_hash << std::dec
              << ", input_size: " << input_size << std::endl;

    try {
        auto& logger = sol_compat::MetricsLogger::instance();
        std::string crash_id = "hfuzz_crash_" + std::to_string(s_total_crashes.load());

        logger.log_bug_discovery(
            crash_id,
            "honggfuzz",
            "",  // file
            "",  // function
            0,   // line
            "crash",
            "high",
            "new",
            0,   // reproduction_time_ms
            input_size,
            description ? description : "Crash detected by honggfuzz"
        );
    } catch (const std::exception& e) {
        std::cerr << "[hfuzz_metrics_bridge] Error logging crash: "
                  << e.what() << std::endl;
    }
}

/*
 * Log a hang/timeout detection.
 */
void hfuzz_metrics_bridge_log_hang(size_t input_size, uint64_t timeout_ms) {
    if (!s_session_initialized.load()) {
        return;
    }

    s_total_hangs.fetch_add(1, std::memory_order_relaxed);
    s_total_input_bytes.fetch_add(input_size, std::memory_order_relaxed);

    std::cerr << "[hfuzz_metrics_bridge] Hang detected - timeout: "
              << timeout_ms << "ms, input_size: " << input_size << std::endl;

    try {
        auto& logger = sol_compat::MetricsLogger::instance();
        std::string hang_id = "hfuzz_hang_" + std::to_string(s_total_hangs.load());

        logger.log_bug_discovery(
            hang_id,
            "honggfuzz",
            "",  // file
            "",  // function
            0,   // line
            "hang",
            "medium",
            "new",
            0,   // reproduction_time_ms
            input_size,
            "Execution timeout after " + std::to_string(timeout_ms) + "ms"
        );
    } catch (const std::exception& e) {
        std::cerr << "[hfuzz_metrics_bridge] Error logging hang: "
                  << e.what() << std::endl;
    }
}

/*
 * Log coverage metrics update.
 * Uses time-based throttling to avoid overhead.
 */
void hfuzz_metrics_bridge_log_coverage(uint64_t new_pcs,
                                 uint64_t new_edges,
                                 uint64_t new_cmp,
                                 uint64_t total_pcs,
                                 uint64_t total_edges,
                                 uint64_t total_cmp,
                                 size_t corpus_count) {
    if (!s_session_initialized.load()) {
        return;
    }

    // Always cache latest coverage values (used by log_execution)
    s_latest_pcs.store(total_pcs, std::memory_order_relaxed);
    s_latest_edges.store(total_edges, std::memory_order_relaxed);
    s_latest_cmp.store(total_cmp, std::memory_order_relaxed);
    s_latest_corpus_count.store(corpus_count, std::memory_order_relaxed);
    s_new_coverage.fetch_add(new_pcs + new_edges, std::memory_order_relaxed);

    // Check if enough time has passed since last metrics log
    auto now = std::chrono::steady_clock::now();
    auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
        now - s_last_metrics_time);

    if (time_since_last < METRICS_INTERVAL) {
        return;  // Skip - not enough time has passed
    }

    s_last_metrics_time = now;

    // Log coverage update (for debugging)
    std::cerr << "[hfuzz_metrics_bridge] Coverage update - "
              << "new_pcs: " << new_pcs
              << ", new_edges: " << new_edges
              << ", total_pcs: " << total_pcs
              << ", total_edges: " << total_edges
              << ", corpus: " << corpus_count << std::endl;

    // NOTE: We no longer call log_execution_metrics here because:
    // 1. log_fuzzer_stats is called every 150s from input.c with complete stats
    // 2. log_execution_metrics creates events with zeros for all stats fields
    //    (sched, decay, health, diff-fuzz), which pollutes the timeseries data
    // 3. The coverage values are already included in log_fuzzer_stats events
}

/*
 * Log detailed coverage map for source-level analysis.
 * Counts covered guards from the honggfuzz guard map.
 */
void hfuzz_metrics_bridge_log_detailed_coverage(const uint8_t* guard_map,
                                          uint64_t guard_count) {
    if (!s_session_initialized.load()) {
        return;
    }

    // Throttle detailed coverage logging (expensive operation)
    auto now = std::chrono::steady_clock::now();
    auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
        now - s_last_detailed_coverage_time);

    if (time_since_last < DETAILED_COVERAGE_INTERVAL) {
        return;  // Skip - not enough time has passed
    }
    s_last_detailed_coverage_time = now;

    // Count covered guards
    uint64_t covered_guards = 0;
    if (guard_map && guard_count > 0) {
        for (uint64_t i = 0; i < guard_count; i++) {
            if (guard_map[i] > 0) {
                covered_guards++;
            }
        }
    }

    // Update denominator if not set
    if (s_coverage_denominator.load() == 0 && guard_count > 0) {
        s_coverage_denominator.store(guard_count, std::memory_order_relaxed);
    }

    uint64_t denominator = s_coverage_denominator.load();
    double coverage_pct = denominator > 0
        ? (static_cast<double>(covered_guards) / denominator) * 100.0
        : 0.0;

    std::cerr << "[hfuzz_metrics_bridge] Detailed coverage: "
              << covered_guards << "/" << denominator
              << " guards (" << std::fixed << std::setprecision(2)
              << coverage_pct << "%)" << std::endl;

    // Log per-module coverage breakdown
    {
        std::lock_guard<std::mutex> lock(s_modules_mutex);
        for (const auto& mod : s_registered_modules) {
            uint64_t mod_covered = 0;
            uint32_t end = mod.guard_start + mod.guard_count;
            if (end > guard_count) end = guard_count;

            for (uint32_t i = mod.guard_start; i < end; i++) {
                if (guard_map[i] > 0) {
                    mod_covered++;
                }
            }

            double mod_pct = mod.guard_count > 0
                ? (static_cast<double>(mod_covered) / mod.guard_count) * 100.0
                : 0.0;

            std::cerr << "[hfuzz_metrics_bridge]   Module " << mod.name
                      << ": " << mod_covered << "/" << mod.guard_count
                      << " (" << std::fixed << std::setprecision(2)
                      << mod_pct << "%)" << std::endl;
        }
    }

}

/*
 * Register a newly instrumented module for coverage tracking.
 * NOTE: This function is called during static initialization (from module constructors)
 * so we MUST NOT use std::cerr or any C++ I/O streams here - they may not be initialized yet.
 */
void hfuzz_metrics_bridge_register_module(const char* module_name,
                                    uint64_t guard_start,
                                    uint64_t guard_count) {
    std::lock_guard<std::mutex> lock(s_modules_mutex);

    // Check if already registered
    for (const auto& mod : s_registered_modules) {
        if (mod.guard_start == guard_start && mod.guard_count == guard_count) {
            return;  // Already registered
        }
    }

    ModuleInfo info;
    info.name = module_name ? module_name : "unknown";
    info.guard_start = guard_start;
    info.guard_count = guard_count;
    // pc_table will be populated by hfuzz_metrics_register_pc_table
    s_registered_modules.push_back(std::move(info));

    // Only log after session is initialized (std::cerr may not be safe during static init)
    // Module registration info will be logged when the session starts
}

/*
 * Spinlock helpers for module registration (matches honggfuzz pattern).
 * Uses simple test-and-set spinlock with timeout for safety.
 */
static inline bool pc_table_spinlock_acquire(PCTableShmHeader* header) {
    const uint64_t MAX_SPINS = 100000000ULL;  // ~10s at 10M spins/s
    uint64_t spins = 0;

    for (;;) {
        // Spin while lock is held
        while (__atomic_load_n(&header->registration_lock, __ATOMIC_RELAXED) != 0) {
            #if defined(__x86_64__) || defined(__i386__)
            __builtin_ia32_pause();
            #elif defined(__aarch64__)
            __asm__ volatile("yield");
            #else
            __asm__ volatile("" ::: "memory");
            #endif

            if (++spins > MAX_SPINS) {
                fprintf(stderr, "[write_pc_table_to_shm] Spinlock timeout after ~10s\n");
                return false;
            }
        }

        // Try to acquire
        uint32_t expected = 0;
        if (__atomic_compare_exchange_n(&header->registration_lock, &expected, 1,
                                        false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            return true;
        }
        // Someone else got it, retry
    }
}

static inline void pc_table_spinlock_release(PCTableShmHeader* header) {
    __atomic_store_n(&header->registration_lock, 0, __ATOMIC_RELEASE);
}

/*
 * Find a registered module by name, pc_count, and guard_start.
 * Can be called with or without the lock (uses acquire ordering on num_modules).
 */
static PCTableModuleEntry* find_registered_module(PCTableShmHeader* header,
                                                   const char* module_name,
                                                   uint64_t pc_count,
                                                   uint64_t guard_start) {
    // ACQUIRE load synchronizes with RELEASE store when count is incremented.
    // This ensures we see all writes to module_registry[0..count-1]
    uint64_t count = __atomic_load_n(&header->num_modules, __ATOMIC_ACQUIRE);
    for (uint64_t i = 0; i < count && i < PC_TABLE_MAX_MODULES; i++) {
        PCTableModuleEntry* entry = &header->module_registry[i];
        if (entry->guard_start == guard_start &&
            entry->pc_count == pc_count &&
            strncmp(entry->module_name, module_name, PC_TABLE_MODULE_NAME_SIZE) == 0) {
            return entry;
        }
    }
    return nullptr;
}

/*
 * Write PC table entry to shared memory (child process during static init).
 * Uses POSIX shm_open/mmap which work during static initialization.
 *
 * IMPORTANT: We store RELATIVE PCs (offset from module base) so the parent
 * can use addr2line directly without needing the addresses to be valid
 * in its address space.
 *
 * DEDUPLICATION: Uses double-checked locking pattern (same as honggfuzz):
 * 1. Quick optimistic check without lock (common case: already registered)
 * 2. Acquire spinlock
 * 3. Double-check under lock (another process might have registered while waiting)
 * 4. Do the actual work (reserve space, write data)
 * 5. Release spinlock
 */
static void write_pc_table_to_shm(const char* module_name,
                                   const hfuzz_pc_entry_t* pcs,
                                   size_t pc_count,
                                   uint64_t guard_start) {
    // NOTE: This runs during static initialization in child processes.
    // Errors are logged to stderr but don't abort - fuzzing can continue without PC table.

    // Get shm name from environment (set by parent process)
    const char* shm_name = getenv("SOLFUZZ_PC_TABLE_SHM");

    if (!shm_name || !*shm_name) {
        // Parent didn't set up shm - this is normal if ClickHouse metrics are disabled
        return;
    }

    // Open existing shared memory
    int shm_fd = shm_open(shm_name, O_RDWR, 0644);
    if (shm_fd < 0) {
        int err = errno;
        fprintf(stderr, "[write_pc_table_to_shm] ERROR: shm_open('%s') failed: %s (errno=%d)\n",
                shm_name, strerror(err), err);
        return;
    }

    // Map the memory
    void* shm_ptr = mmap(nullptr, PC_TABLE_SHM_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED, shm_fd, 0);
    int mmap_err = errno;
    close(shm_fd);  // Don't need fd after mmap

    if (shm_ptr == MAP_FAILED) {
        fprintf(stderr, "[write_pc_table_to_shm] ERROR: mmap failed: %s (errno=%d)\n",
                strerror(mmap_err), mmap_err);
        return;
    }

    PCTableShmHeader* header = static_cast<PCTableShmHeader*>(shm_ptr);

    // Verify magic
    if (header->magic != PC_TABLE_SHM_MAGIC) {
        fprintf(stderr, "[write_pc_table_to_shm] ERROR: Invalid shm magic 0x%x (expected 0x%x)\n",
                header->magic, PC_TABLE_SHM_MAGIC);
        munmap(shm_ptr, PC_TABLE_SHM_SIZE);
        return;
    }

    const char* safe_module_name = module_name ? module_name : "unknown";

    // =========================================================================
    // STEP 1: Quick optimistic check WITHOUT lock (common case: already registered)
    // =========================================================================
    PCTableModuleEntry* existing = find_registered_module(header, safe_module_name, pc_count, guard_start);
    if (existing) {
        // Already registered by another process
        munmap(shm_ptr, PC_TABLE_SHM_SIZE);
        return;
    }

    // =========================================================================
    // STEP 2: Not found - acquire spinlock
    // =========================================================================
    if (!pc_table_spinlock_acquire(header)) {
        munmap(shm_ptr, PC_TABLE_SHM_SIZE);
        return;
    }

    // =========================================================================
    // STEP 3: Double-check under lock (another process might have registered while we waited)
    // =========================================================================
    existing = find_registered_module(header, safe_module_name, pc_count, guard_start);
    if (existing) {
        pc_table_spinlock_release(header);
        munmap(shm_ptr, PC_TABLE_SHM_SIZE);
        return;
    }

    // =========================================================================
    // STEP 4: Do the actual work - we hold the lock, safe to proceed
    // =========================================================================

    // Check if registry is full
    uint64_t slot = __atomic_load_n(&header->num_modules, __ATOMIC_RELAXED);
    if (slot >= PC_TABLE_MAX_MODULES) {
        fprintf(stderr, "[write_pc_table_to_shm] WARNING: Module registry full (%lu modules), skipping %s\n",
                (unsigned long)slot, safe_module_name);
        pc_table_spinlock_release(header);
        munmap(shm_ptr, PC_TABLE_SHM_SIZE);
        return;
    }

    // Get module base address using dladdr on the first PC
    uintptr_t module_base = 0;
    bool is_pie_or_shared = false;
    if (pc_count > 0 && pcs[0].pc != 0) {
        Dl_info info;
        if (dladdr(reinterpret_cast<void*>(pcs[0].pc), &info) && info.dli_fbase) {
            module_base = reinterpret_cast<uintptr_t>(info.dli_fbase);
            is_pie_or_shared = (module_base >= 0x100000000ULL);
        }
    }

    // Calculate size needed for this module
    size_t module_data_size = sizeof(PCTableShmModule) + pc_count * sizeof(PCTableShmEntry);

    // Reserve space (still need atomic since reader might be active)
    uint64_t write_offset = __atomic_fetch_add(&header->next_write_offset, module_data_size, __ATOMIC_ACQ_REL);

    // Check if we have enough space
    if (write_offset + module_data_size > PC_TABLE_SHM_SIZE) {
        fprintf(stderr, "[write_pc_table_to_shm] ERROR: Out of shared memory space! "
                "offset=%lu + size=%zu > max=%zu (module=%s, pc_count=%zu)\n",
                (unsigned long)write_offset, module_data_size, PC_TABLE_SHM_SIZE,
                safe_module_name, pc_count);
        pc_table_spinlock_release(header);
        munmap(shm_ptr, PC_TABLE_SHM_SIZE);
        return;
    }

    // Write module data
    uint8_t* data_ptr = static_cast<uint8_t*>(shm_ptr) + write_offset;
    PCTableShmModule* shm_mod = reinterpret_cast<PCTableShmModule*>(data_ptr);

    memset(shm_mod->module_name, 0, PC_TABLE_MODULE_NAME_SIZE);
    strncpy(shm_mod->module_name, safe_module_name, PC_TABLE_MODULE_NAME_SIZE - 1);
    shm_mod->guard_start = guard_start;
    shm_mod->pc_count = pc_count;
    shm_mod->module_base = is_pie_or_shared ? module_base : 0;
    shm_mod->reserved = 0;

    // Write PC entries
    PCTableShmEntry* entries = reinterpret_cast<PCTableShmEntry*>(data_ptr + sizeof(PCTableShmModule));
    for (size_t i = 0; i < pc_count; i++) {
        uintptr_t abs_pc = pcs[i].pc;
        uintptr_t stored_pc;
        if (is_pie_or_shared && module_base != 0 && abs_pc >= module_base) {
            stored_pc = abs_pc - module_base;
        } else {
            stored_pc = abs_pc;
        }
        entries[i].pc = stored_pc;
        entries[i].flags = pcs[i].flags;
    }

    // Register in module registry (write entry data first)
    PCTableModuleEntry* reg_entry = &header->module_registry[slot];
    strncpy(reg_entry->module_name, safe_module_name, PC_TABLE_MODULE_NAME_SIZE - 1);
    reg_entry->module_name[PC_TABLE_MODULE_NAME_SIZE - 1] = '\0';
    reg_entry->pc_count = pc_count;
    reg_entry->guard_start = guard_start;

    // Memory barrier to ensure all writes are visible before updating counts
    __atomic_thread_fence(__ATOMIC_RELEASE);

    // RELEASE store ensures entry writes are visible before count increment.
    // This synchronizes with ACQUIRE load in find_registered_module().
    __atomic_store_n(&header->num_modules, slot + 1, __ATOMIC_RELEASE);
    __atomic_fetch_add(&header->total_entries, static_cast<uint64_t>(pc_count), __ATOMIC_ACQ_REL);

    // =========================================================================
    // STEP 5: Release spinlock
    // =========================================================================
    pc_table_spinlock_release(header);

    if (debug_logging_enabled()) {
        FILE* dbg = fopen("/tmp/shm_debug.log", "a");
        if (dbg) {
            fprintf(dbg, "[write_pc_table_to_shm] pid=%d, module=%s, pc_count=%zu, module_base=0x%lx, is_pie=%d, first_pc=0x%lx, wrote at offset=%lu, slot=%lu\n",
                    getpid(), safe_module_name, pc_count,
                    (unsigned long)module_base, is_pie_or_shared ? 1 : 0,
                    pc_count > 0 ? (unsigned long)entries[0].pc : 0,
                    (unsigned long)write_offset, (unsigned long)slot);
            fclose(dbg);
        }
    }

    // Unmap
    munmap(shm_ptr, PC_TABLE_SHM_SIZE);
}

/*
 * Register PC table for symbolization of coverage.
 * NOTE: This function is called during static initialization (from module constructors)
 * so we MUST NOT use std::cerr or any C++ I/O streams here - they may not be initialized yet.
 *
 * This writes PC table data to a file that the parent process can read.
 */
void hfuzz_metrics_bridge_register_pc_table(const char* module_name,
                                      const hfuzz_pc_entry_t* pcs,
                                      size_t pc_count,
                                      uint64_t guard_start) {
    if (!pcs || pc_count == 0) {
        return;
    }

    // Safety check: Ensure module_data_size won't overflow shared memory
    constexpr size_t MAX_SAFE_PC_COUNT = (PC_TABLE_SHM_SIZE - sizeof(PCTableShmHeader) - sizeof(PCTableShmModule)) / sizeof(PCTableShmEntry);
    if (pc_count > MAX_SAFE_PC_COUNT) {
        fprintf(stderr, "[hfuzz_metrics_bridge] WARNING: pc_count %zu exceeds safe limit %zu for a single module\n",
                pc_count, MAX_SAFE_PC_COUNT);
        // Don't write to shm - would exceed bounds
        return;
    }

    // Write PC table to shared memory for parent process to read
    // This is safe during static init (uses POSIX shm_open/mmap syscalls)
    write_pc_table_to_shm(module_name, pcs, pc_count, guard_start);

    std::lock_guard<std::mutex> lock(s_modules_mutex);

    // Find the matching module
    ModuleInfo* target_module = nullptr;
    for (auto& mod : s_registered_modules) {
        if (mod.guard_start == guard_start && mod.guard_count == pc_count) {
            target_module = &mod;
            break;
        }
    }

    if (!target_module) {
        // Module not found - create a new one
        ModuleInfo info;
        info.name = module_name ? module_name : "unknown";
        info.guard_start = guard_start;
        info.guard_count = static_cast<uint32_t>(pc_count);
        s_registered_modules.push_back(std::move(info));
        target_module = &s_registered_modules.back();
    }

    // Copy the PC table (for child process local use)
    target_module->pc_table.clear();
    target_module->pc_table.reserve(pc_count);
    for (size_t i = 0; i < pc_count; i++) {
        PCEntry entry;
        entry.pc = pcs[i].pc;
        entry.flags = pcs[i].flags;
        target_module->pc_table.push_back(entry);
    }

    // Only log after session is initialized (std::cerr may not be safe during static init)
    // PC table registration info will be logged when the session starts
}

/*
 * Helper: symbolize a PC address to "function (file:line)" format.
 */
static std::string symbolize_pc(uintptr_t pc) {
    Dl_info info;
    if (dladdr(reinterpret_cast<void*>(pc), &info)) {
        std::ostringstream oss;
        if (info.dli_sname) {
            oss << info.dli_sname;
        } else {
            oss << "0x" << std::hex << pc;
        }
        if (info.dli_fname) {
            // Extract basename
            const char* basename = strrchr(info.dli_fname, '/');
            basename = basename ? basename + 1 : info.dli_fname;
            oss << " (" << basename << ")";
        }
        return oss.str();
    }
    std::ostringstream oss;
    oss << "0x" << std::hex << pc;
    return oss.str();
}

/*
 * Log full coverage report including uncovered guards.
 */
void hfuzz_metrics_bridge_log_full_coverage_report(const uint8_t* guard_map,
                                             uint64_t guard_count,
                                             const char* output_path) {
    if (!guard_map || guard_count == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(s_modules_mutex);

    // Build coverage data structure
    struct FileCoverage {
        std::string path;
        std::vector<uint32_t> covered_lines;
        std::vector<uint32_t> uncovered_lines;
        std::vector<std::string> covered_functions;
        std::vector<std::string> uncovered_functions;
    };
    std::unordered_map<std::string, FileCoverage> file_coverage;

    // Also track function-level coverage
    struct FunctionCov {
        std::string name;
        std::string file;
        uintptr_t pc;
        bool covered;
        uint64_t hits;
    };
    std::vector<FunctionCov> function_list;

    uint64_t total_covered = 0;
    uint64_t total_uncovered = 0;

    // Process each module
    for (const auto& mod : s_registered_modules) {
        if (mod.pc_table.empty()) {
            continue;  // No PC table for this module
        }

        for (size_t i = 0; i < mod.pc_table.size() && i < mod.guard_count; i++) {
            uint32_t guard_idx = mod.guard_start + static_cast<uint32_t>(i);
            if (guard_idx >= guard_count) {
                break;
            }

            const auto& pc_entry = mod.pc_table[i];
            bool is_covered = guard_map[guard_idx] > 0;
            uint8_t hit_count = guard_map[guard_idx];

            if (is_covered) {
                total_covered++;
            } else {
                total_uncovered++;
            }

            // Symbolize the PC
            Dl_info info;
            if (dladdr(reinterpret_cast<void*>(pc_entry.pc), &info)) {
                std::string file_path = info.dli_fname ? info.dli_fname : mod.name;
                std::string func_name = info.dli_sname ? info.dli_sname : "??";

                // Track function coverage for function entry points
                if (pc_entry.is_function_entry()) {
                    FunctionCov fcov;
                    fcov.name = func_name;
                    fcov.file = file_path;
                    fcov.pc = pc_entry.pc;
                    fcov.covered = is_covered;
                    fcov.hits = hit_count;
                    function_list.push_back(fcov);

                    // Add to file's function lists
                    auto& fc = file_coverage[file_path];
                    fc.path = file_path;
                    if (is_covered) {
                        fc.covered_functions.push_back(func_name);
                    } else {
                        fc.uncovered_functions.push_back(func_name);
                    }
                }
            }
        }
    }

    // Log summary
    uint64_t total = total_covered + total_uncovered;
    double pct = total > 0 ? (100.0 * total_covered / total) : 0.0;

    std::cerr << "[hfuzz_metrics_bridge] Full coverage report: "
              << total_covered << "/" << total << " guards covered ("
              << std::fixed << std::setprecision(2) << pct << "%)" << std::endl;

    // Count covered/uncovered functions
    size_t covered_funcs = 0, uncovered_funcs = 0;
    for (const auto& f : function_list) {
        if (f.covered) covered_funcs++;
        else uncovered_funcs++;
    }
    std::cerr << "[hfuzz_metrics_bridge] Function coverage: "
              << covered_funcs << "/" << (covered_funcs + uncovered_funcs) << std::endl;

    // Write JSON report if output path provided
    if (output_path) {
        std::ofstream ofs(output_path);
        if (ofs) {
            ofs << "{\n";
            ofs << "  \"summary\": {\n";
            ofs << "    \"covered_guards\": " << total_covered << ",\n";
            ofs << "    \"total_guards\": " << total << ",\n";
            ofs << "    \"coverage_percentage\": " << pct << ",\n";
            ofs << "    \"covered_functions\": " << covered_funcs << ",\n";
            ofs << "    \"uncovered_functions\": " << uncovered_funcs << "\n";
            ofs << "  },\n";

            // Covered functions
            ofs << "  \"covered_functions\": [\n";
            bool first = true;
            for (const auto& f : function_list) {
                if (f.covered) {
                    if (!first) ofs << ",\n";
                    first = false;
                    ofs << "    {\"name\": \"" << f.name << "\", \"file\": \""
                        << f.file << "\", \"hits\": " << f.hits << "}";
                }
            }
            ofs << "\n  ],\n";

            // Uncovered functions
            ofs << "  \"uncovered_functions\": [\n";
            first = true;
            for (const auto& f : function_list) {
                if (!f.covered) {
                    if (!first) ofs << ",\n";
                    first = false;
                    ofs << "    {\"name\": \"" << f.name << "\", \"file\": \""
                        << f.file << "\", \"pc\": \"0x" << std::hex << f.pc << std::dec << "\"}";
                }
            }
            ofs << "\n  ],\n";

            // Per-file summary
            ofs << "  \"files\": [\n";
            first = true;
            for (const auto& [path, fc] : file_coverage) {
                if (!first) ofs << ",\n";
                first = false;
                ofs << "    {\"path\": \"" << path << "\", "
                    << "\"covered_functions\": " << fc.covered_functions.size() << ", "
                    << "\"uncovered_functions\": " << fc.uncovered_functions.size() << "}";
            }
            ofs << "\n  ]\n";

            ofs << "}\n";
            ofs.close();

            std::cerr << "[hfuzz_metrics_bridge] Coverage report written to: "
                      << output_path << std::endl;
        }
    }

    // Also log to MetricsLogger
    try {
        auto& logger = sol_compat::MetricsLogger::instance();

        // Build coverage events for uncovered functions
        std::vector<std::tuple<
            std::string,   // file_path
            std::string,   // function_name
            uint32_t,      // start_line
            uint32_t,      // end_line
            std::string,   // coverage_type
            uint64_t,      // hits
            std::vector<uint32_t>, // line_numbers
            std::vector<uint32_t>  // line_hits
        >> coverage_events;

        for (const auto& f : function_list) {
            coverage_events.emplace_back(
                f.file,
                f.name,
                0,  // start_line (unknown without debug info)
                0,  // end_line
                f.covered ? "covered" : "uncovered",
                f.hits,
                std::vector<uint32_t>{},
                std::vector<uint32_t>{}
            );
        }

        if (!coverage_events.empty()) {
            logger.log_coverage_events_batch(s_target_name, coverage_events, s_target_name);
        }
    } catch (const std::exception& e) {
        std::cerr << "[hfuzz_metrics_bridge] Error logging to ClickHouse: "
                  << e.what() << std::endl;
    }
}

/*
 * Log comprehensive fuzzer statistics (SCHED/DECAY/HEALTH/DIFF-FUZZ stats).
 * Called periodically from honggfuzz input.c after the LOG_I stats calls.
 */
void hfuzz_metrics_bridge_log_stats(
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
    uint64_t inputs_truncated_too_large
) {
    if (!s_session_initialized.load()) {
        return;
    }

    std::cerr << "[hfuzz_metrics_bridge] Stats update - "
              << "state: " << (fuzzer_state ? fuzzer_state : "unknown")
              << ", total_execs: " << total_executions
              << ", exec_avg_us: " << exec_avg_us
              << ", sched: " << sched_total
              << ", repeat: " << repeat_pct << "%"
              << ", energy: " << avg_energy
              << ", mut_hit_rate: " << mut_hit_rate_pct << "%"
              << ", plateau: " << plateau_secs << "s"
              << ", corpus: " << corpus_count
              << ", crashes: " << unique_crashes << std::endl;

    try {
        auto& logger = sol_compat::MetricsLogger::instance();
        logger.log_fuzzer_stats(
            total_executions,
            coverage_pcs, coverage_edges, coverage_cmp, coverage_edge_bucket,
            sched_total, repeat_pct, high_pct, low_pct, phase2_pct, avg_energy, avg_iters, max_iters, energy_min, energy_max,
            novelty_decay, fresh_boost, stale_penalty, diminishing, depth_penalty, corpus_count, global_avg_energy,
            exec_avg_us, exec_max_us, slow_execs, mut_hit_rate_pct, plateau_secs, queue_wraps, max_depth,
            unique_crashes, total_crashes, timeouts, fertile_boosts, saturated, explore_selects, secs_since_crash, stagnation_secs, corpus_growth,
            fuzzer_state ? fuzzer_state : "unknown", dry_run_tested, dry_run_total,
            inputs_truncated_too_large
        );
    } catch (const std::exception& e) {
        std::cerr << "[hfuzz_metrics_bridge] Error logging stats: "
                  << e.what() << std::endl;
    }
}

void hfuzz_metrics_bridge_log_mutation_health(
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
    uint64_t elf_fixup_ok_cnt,
    uint64_t exec_fail_cnt,
    uint64_t verify_cnt,
    uint64_t harness_reject_cnt
) {
    if (!s_session_initialized.load()) {
        return;
    }

    float proto_parse_pct = proto_parse_calls > 0
        ? (100.0f * proto_parse_successes / proto_parse_calls) : 0.0f;
    float custom_mut_pct = custom_mutator_calls > 0
        ? (100.0f * custom_mutator_successes / custom_mutator_calls) : 0.0f;

    std::cerr << "[hfuzz_metrics_bridge] Mutation health - "
              << "proto_parse: " << proto_parse_successes << "/" << proto_parse_calls
              << " (" << std::fixed << std::setprecision(1) << proto_parse_pct << "%)"
              << ", custom_mut: " << custom_mutator_successes << "/" << custom_mutator_calls
              << " (" << custom_mut_pct << "%)"
              << ", kutator_mutate: " << kutator_mutate_cnt
              << ", kutator_crossover: " << kutator_crossover_cnt
              << ", parse_ok: " << kutator_parse_success_cnt
              << ", parse_fail: " << kutator_parse_fail_cnt
              << ", enc_overflow: " << encode_overflow_cnt
              << ", no_candidates: " << no_candidates_cnt
              << ", kinds[" << kind_num << "]={";
    for (uint32_t k = 0; k < kind_num; k++) {
        if (k > 0) std::cerr << ", ";
        std::cerr << (kind_names[k] ? kind_names[k] : "?") << "=" << kind_counts[k];
    }
    std::cerr << "}"
              << ", exec_fail: " << exec_fail_cnt
              << ", harness_reject: " << harness_reject_cnt
              << std::endl;

    try {
        auto& logger = sol_compat::MetricsLogger::instance();
        logger.log_mutation_health(
            total_executions,
            proto_parse_calls, proto_parse_successes,
            custom_mutator_calls, custom_mutator_successes,
            proto_parse_pct,
            proto_round_cnt, proto_scan_ok_cnt, total_round_cnt,
            kutator_mutate_cnt, kutator_crossover_cnt, kutator_parse_success_cnt, kutator_parse_fail_cnt,
            encode_overflow_cnt, no_candidates_cnt,
            kind_counts, kind_names, kind_num,
            elf_fixup_ok_cnt, exec_fail_cnt, verify_cnt, harness_reject_cnt
        );
    } catch (const std::exception& e) {
        std::cerr << "[hfuzz_metrics_bridge] Error logging mutation health: "
                  << e.what() << std::endl;
    }
}

} // extern "C"

