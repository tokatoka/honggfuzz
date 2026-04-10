#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

// Use LLVM symbolizer when available (not in shared library builds)
// When disabled, falls back to dladdr + addr2line
#if !defined(SOLFUZZ_SHARED_LIB) && !defined(SOLFUZZ_NO_LLVM_SYMBOLIZER)
#define SOLFUZZ_USE_LLVM_SYMBOLIZER 1
#endif

#if defined(SOLFUZZ_USE_LLVM_SYMBOLIZER)
namespace llvm {
namespace symbolize {
class LLVMSymbolizer;
}
}
#endif

namespace sol_compat {

// PC => source location and function info (with inline frames)
struct PcLocation {
  struct FrameLocation {
    std::string file;
    uint32_t line = 0;
    std::string func;   // demangled
    std::string module; // full path
  };

  // Full inline chain, outermost first
  std::vector<FrameLocation> frames;
};

// Symbol resolution and module filtering
class CoverageSymbolizer {
public:
  static CoverageSymbolizer& instance();

  // Filtering
  void init_module_filter();
  bool is_module_allowed_for_logging(const char *module_path);
  bool is_source_file_allowed_for_logging(const std::string &file_path);
  bool is_symbol_name_excluded(const std::string &name_with_optional_suffix);

  // Resolve a single PC to a symbol name
  std::string resolve_symbol(uintptr_t pc);

  // Batch resolve multiple PCs to symbols and locations
  void batch_resolve_symbols(const std::vector<uintptr_t> &pcs);

  // Batch resolve symbols for a specific module using relative PCs
  // This bypasses dladdr and works when PCs are not in the current process
  void batch_resolve_for_module(const std::string& module_path,
                                 const std::vector<std::pair<uintptr_t, uintptr_t>>& rel_pcs_and_flags);

  // Get source location for a PC (if available)
  bool get_pc_location(uintptr_t pc, PcLocation &loc);
  
  // Get source location using relative PC and module path (bypasses dladdr)
  bool get_pc_location_for_module(const std::string& module_path, 
                                   uintptr_t rel_pc, 
                                   PcLocation& loc);

  // Check if module filter is enabled
  bool is_module_filter_enabled() const { return module_filter_enabled_; }

  const std::unordered_set<std::string>& get_allowed_module_basenames() const {
    return allowed_module_basenames_;
  }

  const std::unordered_map<uintptr_t, std::string>& get_symbol_cache() const {
    return symbol_cache_;
  }

private:
  CoverageSymbolizer() = default;
  ~CoverageSymbolizer() = default;
  CoverageSymbolizer(const CoverageSymbolizer&) = delete;
  CoverageSymbolizer& operator=(const CoverageSymbolizer&) = delete;

  // Module filtering state
  bool module_filter_inited_ = false;
  bool module_filter_enabled_ = false;
  std::unordered_set<std::string> allowed_module_basenames_;
  std::unordered_set<std::string> allowed_module_fullpaths_;
  std::vector<std::string> allowed_source_prefixes_;

  // Symbol caches (absolute PCs — used by batch_resolve_symbols / resolve_symbol)
  std::unordered_map<uintptr_t, std::string> symbol_cache_;
  std::unordered_map<uintptr_t, PcLocation> pc_loc_cache_;
  // Per-module caches (relative PCs — used by batch_resolve_for_module)
  std::unordered_map<std::string, std::unordered_map<uintptr_t, std::string>> module_symbol_cache_;
  std::unordered_map<std::string, std::unordered_map<uintptr_t, PcLocation>> module_pc_loc_cache_;
  std::unordered_map<std::string, bool> module_is_dyn_cache_;

  // Helpers
  std::string trim_copy(const std::string &s);
  std::string basename_copy(const char *path);
  std::string normalize_path(const std::string &path);  // Resolve '../' in paths
  bool parse_file_colon_line(const char *s, std::string &out_file, uint32_t &out_line);
  std::string format_rust_legacy_symbol(const std::string &name);
  std::string demangle_rust_like(const std::string &name);
  bool module_is_dyn(const std::string &binary_path);
  bool parse_addr2line_output(FILE* pipe, std::array<char, 2048>& buffer,
                              std::string& func_name,
                              std::string* src_file = nullptr,
                              uint32_t* src_line = nullptr);
  std::string resolve_symbol_with_addr2line(uintptr_t pc, const std::string &binary_path);

#if defined(SOLFUZZ_USE_LLVM_SYMBOLIZER)
  llvm::symbolize::LLVMSymbolizer& get_llvm_symbolizer();
#endif
};

} // namespace sol_compat

