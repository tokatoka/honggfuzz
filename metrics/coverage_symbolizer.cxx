#include "coverage_symbolizer.h"

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <cxxabi.h>
#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <array>
#include <memory>
#include <unordered_set>
#include <sys/wait.h>

// Use LLVM symbolizer when enabled in header (falls back to dladdr + addr2line)
#if defined(SOLFUZZ_USE_LLVM_SYMBOLIZER)
#include <llvm/Config/llvm-config.h>
#include <llvm/DebugInfo/Symbolize/Symbolize.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/Support/Error.h>
#endif

namespace sol_compat {

// Debug logging control - uses same env var as hfuzz_metrics_bridge
static bool symbolizer_debug_enabled() {
    static bool enabled = []() {
        const char* env = std::getenv("SOLFUZZ_COVERAGE_DEBUG");
        return env && std::string(env) == "1";
    }();
    return enabled;
}

#define SYM_DEBUG(...) do { \
    if (symbolizer_debug_enabled()) { \
        std::cerr << __VA_ARGS__; \
    } \
} while(0)

// SECURITY: Validate file path for use in shell commands
// Returns true if the path contains only safe characters
static bool is_safe_shell_path(const std::string& path) {
  if (path.empty()) return false;
  // Check for path traversal
  if (path.find("..") != std::string::npos) return false;
  // Only allow safe characters: alphanumeric, dots, underscores, hyphens, slashes, plus signs
  for (char c : path) {
    if (!std::isalnum(c) && c != '.' && c != '_' && c != '-' && c != '/' && c != '+') {
      return false;
    }
  }
  return true;
}

// SECURITY: Shell-escape a path for use in single-quoted context
// For single quotes, we close the quote, escape with backslash, and reopen
static std::string shell_escape_path(const std::string& path) {
  std::string escaped;
  escaped.reserve(path.size() + 10);
  escaped += '\'';
  for (char c : path) {
    if (c == '\'') {
      escaped += "'\\''";  // Close quote, escaped quote, reopen quote
    } else {
      escaped += c;
    }
  }
  escaped += '\'';
  return escaped;
}

// Rust symbol name prefix filter denylist
static const char *k_excluded_symbol_prefixes[] = {
    "core::", "prost::",  "hashbrown::", "alloc::", "once_cell::",
    "std::",  "hash32::", "ahash::",     "bytes::", "getrandom::"};

static const char *k_excluded_exact_names[] = {"__rust_alloc", "__rust_dealloc",
                                               "__rust_realloc"};

CoverageSymbolizer& CoverageSymbolizer::instance() {
  static CoverageSymbolizer inst;
  return inst;
}

// Filter module names that are not meaningful for coverage tracking
void CoverageSymbolizer::init_module_filter() {
  if (module_filter_inited_) {
    return; 
  }
  module_filter_inited_ = true;

  const char *env = std::getenv("SOLFUZZ_TARGETS");
  if (!env || !*env) {
    return;
  }

  // Parse and initialize path allowlist from SOLFUZZ_TARGETS
  std::string value(env);
  size_t pos = 0;
  while (pos <= value.size()) {
    size_t comma = value.find(',', pos);
    std::string token = (comma == std::string::npos)
                            ? value.substr(pos)
                            : value.substr(pos, comma - pos);
    token = trim_copy(token);
    if (!token.empty()) {
      module_filter_enabled_ = true;
      allowed_module_fullpaths_.insert(token);
      allowed_module_basenames_.insert(basename_copy(token.c_str()));
      size_t pos_target = token.find("/target/");
      if (pos_target != std::string::npos && pos_target > 0) {
        allowed_source_prefixes_.push_back(token.substr(0, pos_target));
      }
      size_t pos_fuzz = token.find("/fuzz-build/");
      if (pos_fuzz != std::string::npos && pos_fuzz > 0) {
        allowed_source_prefixes_.push_back(token.substr(0, pos_fuzz));
      }
    }
    if (comma == std::string::npos) {
      break;
    }
    pos = comma + 1;
  }

  // Always allow sources from git checkouts (e.g. solana-sdk) except Cargo registry repos
  const char *home = std::getenv("HOME");
  if (home && *home) {
    std::string p(home);
    if (!p.empty() && p.back() != '/')
      p.push_back('/');
    p += ".cargo/git/checkouts/";
    allowed_source_prefixes_.push_back(std::move(p));
  }

  // Additional absolute source prefixes from SOLFUZZ_SOURCE_PREFIXES allowlist
  const char *src_env = std::getenv("SOLFUZZ_SOURCE_PREFIXES");
  if (src_env && *src_env) {
    std::string sv(src_env);
    size_t s = 0;
    while (s <= sv.size()) {
      size_t comma = sv.find(',', s);
      std::string token =
          (comma == std::string::npos) ? sv.substr(s) : sv.substr(s, comma - s);
      token = trim_copy(token);
      if (!token.empty())
        allowed_source_prefixes_.push_back(token);
      if (comma == std::string::npos)
        break;
      s = comma + 1;
    }
  }
}

bool CoverageSymbolizer::is_module_allowed_for_logging(const char *module_path) {
  if (!module_filter_enabled_) {
    return true; // no filter set => allow all
  }
  if (!module_path || !*module_path) {
    return false; // empty path => deny
  }
  // Fast path: full path match
  if (allowed_module_fullpaths_.find(module_path) !=
      allowed_module_fullpaths_.end()) {
    return true; // full path match => allow
  }
  // Basename match (e.g. "libfuzzer.so" => "libfuzzer")
  std::string base = basename_copy(module_path);
  return allowed_module_basenames_.find(base) !=
         allowed_module_basenames_.end(); // basename match => allow
}

bool CoverageSymbolizer::is_symbol_name_excluded(const std::string &name_with_optional_suffix) {
  // Cached symbol names are often of form: "FuncName (module)". Check prefix on
  // the function part. Some demangled names may start with '<' (e.g., internal
  // names). Ignore leading '<'.
  size_t start = 0;
  while (start < name_with_optional_suffix.size() &&
         name_with_optional_suffix[start] == '<') {
    start++;
  }
  // Exact-name exclusions (optionally followed by a module suffix)
  for (const char *ex : k_excluded_exact_names) {
    size_t elen = std::strlen(ex);
    if (name_with_optional_suffix.size() - start >= elen &&
        name_with_optional_suffix.compare(start, elen, ex) == 0) {
      if (name_with_optional_suffix.size() == start + elen)
        return true;
      char c = name_with_optional_suffix[start + elen];
      if (c == ' ' || c == '(')
        return true;
    }
  }
  // Exclude symbol prefixes (e.g. "core::" => "core::alloc")
  for (const char *p : k_excluded_symbol_prefixes) {
    size_t plen = std::strlen(p);
    if (name_with_optional_suffix.size() - start >= plen &&
        name_with_optional_suffix.compare(start, plen, p) == 0) {
      return true;
    }
  }
  return false; // no match => allow
}

bool CoverageSymbolizer::is_source_file_allowed_for_logging(const std::string &file_path) {
  // Include entries with no file path
  if (file_path.empty()) {
    return true;
  }
  if (!module_filter_enabled_) {
    return true; // no filter set => allow all
  }
  // Exclude cargo registry sources explicitly
  if (file_path.find("/.cargo/registry/src/") != std::string::npos) {
    return false; // cargo registry => deny
  }
  // Allow git checkouts and any provided prefixes (best-effort)
  for (const auto &prefix : allowed_source_prefixes_) {
    if (!prefix.empty() && file_path.rfind(prefix, 0) == 0) {
      return true;
    }
  }
  // Otherwise, default to false under filtering
  return false; // no match => deny
}

// Helper to trim whitespace from a string
std::string CoverageSymbolizer::trim_copy(const std::string &s) {
  size_t start = 0;
  while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
    start++;
  }
  size_t end = s.size();
  while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
    end--;
  }
  return s.substr(start, end - start);
}

// Helper to get the basename of a path
std::string CoverageSymbolizer::basename_copy(const char *path) {
  if (!path || !*path) {
    return std::string();
  }
  const char *last_slash = std::strrchr(path, '/');
  return last_slash ? std::string(last_slash + 1) : std::string(path);
}

// Helper to normalize a file path by resolving '..' and '.' components
// This is critical for coverage tracking - the same file can appear with
// different relative paths (e.g., /src/a/../b/file.h vs /src/b/file.h)
// which causes coverage data to not match the PC registry.
std::string CoverageSymbolizer::normalize_path(const std::string &path) {
  if (path.empty()) {
    return path;
  }
  
  // Use C++17 std::filesystem for safe, portable path normalization
  // lexically_normal() resolves '..' and '.' without touching the filesystem,
  // which is important for source paths that may not exist on this machine.
  try {
    std::filesystem::path p(path);
    return p.lexically_normal().string();
  } catch (const std::exception&) {
    // Fallback to original path if normalization fails
    return path;
  }
}

#if defined(SOLFUZZ_USE_LLVM_SYMBOLIZER)
llvm::symbolize::LLVMSymbolizer& CoverageSymbolizer::get_llvm_symbolizer() {
  // Lazy initialization of LLVM symbolizer
  static bool inited = false;
  static std::unique_ptr<llvm::symbolize::LLVMSymbolizer> sym;
  if (!inited) {
    inited = true;
    llvm::symbolize::LLVMSymbolizer::Options opts;
    opts.Demangle = true;
    opts.UseSymbolTable = true;
    sym = std::make_unique<llvm::symbolize::LLVMSymbolizer>(opts);
  }
  return *sym;
}

// Compatibility helpers to convert LLVM string types to std::string
static inline std::string to_str(const std::string &s) { return s; }
static inline std::string to_str(llvm::StringRef s) { return s.str(); }
#endif

// Helper to parse file:line from addr2line output
bool CoverageSymbolizer::parse_file_colon_line(const char *s, std::string &out_file,
                                         uint32_t &out_line) {
  if (!s || !*s) {
    return false;
  }
  // Remove trailing newline if present
  std::string view(s);
  if (!view.empty() && view.back() == '\n') {
    view.pop_back();
  }
  if (view == "??" || view == "??:0" || view == "?:0") {
    return false;
  }
  size_t colon = view.rfind(':');
  if (colon == std::string::npos) {
    return false; // no colon => invalid
  }
  std::string file = view.substr(0, colon);
  std::string line_str = view.substr(colon + 1);
  if (file == "??" || file.empty()) {
    return false;  // invalid file name
  }
  uint32_t line = 0;
  for (char c : line_str) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return false; // non-digit => invalid
    }
    line = line * 10u + static_cast<uint32_t>(c - '0');
  }
  if (line == 0) {
    return false; // zero line => invalid
  }
  out_file = std::move(file);
  out_line = line;
  return true;
}

// Helper to format Rust legacy symbol names (pre-Rust 1.70)
std::string CoverageSymbolizer::format_rust_legacy_symbol(const std::string &name) {
  // Only transform the function part (before optional " (" module suffix)
  size_t suffix_pos = name.find(" (");
  const std::string head =
      suffix_pos == std::string::npos ? name : name.substr(0, suffix_pos);
  const std::string tail =
      suffix_pos == std::string::npos ? std::string() : name.substr(suffix_pos);

  std::string out;
  out.reserve(head.size());
  for (size_t i = 0; i < head.size();) {
    if (head[i] == '$') {
      // replace $LT$, $GT$, $C$, $uNN$ special tokens with their ASCII equivalents
      if (i + 4 <= head.size() && head.compare(i, 4, "$LT$") == 0) {
        out.push_back('<');
        i += 4;
        continue;
      }
      if (i + 4 <= head.size() && head.compare(i, 4, "$GT$") == 0) {
        out.push_back('>');
        i += 4;
        continue;
      }
      if (i + 4 <= head.size() && head.compare(i, 4, "$LP$") == 0) {
        out.push_back('(');
        i += 4;
        continue;
      }
      if (i + 4 <= head.size() && head.compare(i, 4, "$RP$") == 0) {
        out.push_back(')');
        i += 4;
        continue;
      }
      if (i + 3 <= head.size() && head.compare(i, 3, "$C$") == 0) {
        out.push_back(',');
        i += 3;
        continue;
      }
      if (i + 4 <= head.size() && head.compare(i, 4, "$RF$") == 0) {
        out.push_back('&');
        i += 4;
        continue;
      }
      // Handle $uHH$ where HH are hex until '$'
      if (i + 5 <= head.size() && head[i + 1] == 'u') {
        // $uHH$ where HH are hex until '$'
        size_t j = i + 2;
        unsigned value = 0;
        bool ok = true;
        for (; j < head.size() && head[j] != '$'; ++j) {
          char c = head[j];
          value *= 16;
          if (c >= '0' && c <= '9')
            value += (c - '0');
          else if (c >= 'a' && c <= 'f')
            value += (c - 'a' + 10);
          else if (c >= 'A' && c <= 'F')
            value += (c - 'A' + 10);
          else {
            ok = false;
            break;
          }
        }
        if (ok && j < head.size() && head[j] == '$') {
          // Only map ASCII for safety
          if (value <= 0x7F)
            out.push_back(static_cast<char>(value));
          i = j + 1;
          continue;
        }
      }
    }
    out.push_back(head[i]);
    ++i;
  }
  // Replace Rust path ".." with C++-style scope "::"
  for (size_t pos = 0; (pos = out.find("..", pos)) != std::string::npos;) {
    out.replace(pos, 2, "::");
    pos += 2;
  }
  return out + tail;
}

// Helper to demangle Rust-like symbol names using LLVM demangler if available,
// otherwise fallback to legacy formatting (pre-Rust 1.70)
std::string CoverageSymbolizer::demangle_rust_like(const std::string &name) {
#if defined(SOLFUZZ_USE_LLVM_SYMBOLIZER)
  // Try LLVM demangler first
  std::string dem = llvm::demangle(name);
  // If demangled name is different, strip leading '_' added before '<'
  if (!dem.empty() && dem != name) {
    // Drop legacy leading '_' added before '<'
    if (dem.size() > 1 && dem[0] == '_' && dem[1] == '<')
      dem.erase(0, 1);
    return dem;
  }
#endif
  // Fallback to legacy formatting
  std::string fmt = format_rust_legacy_symbol(name);
  // If legacy name is different, strip leading '_' added before '<'
  if (fmt.size() > 1 && fmt[0] == '_' && fmt[1] == '<') {
    // Drop legacy leading '_' added before '<'
    fmt.erase(0, 1);
  }
  return fmt;
}

// Cached helper to check if a module is dynamically linked (shared object)
bool CoverageSymbolizer::module_is_dyn(const std::string &binary_path) {
  auto it = module_is_dyn_cache_.find(binary_path);
  if (it != module_is_dyn_cache_.end()) {
    return it->second;
  }
  // Heuristic: shared objects usually end with .so
  if (binary_path.rfind(".so") != std::string::npos) {
    module_is_dyn_cache_[binary_path] = true;
    return true;
  }
  // Otherwise, use readelf to check the ELF type
  // SECURITY: Validate and escape the path to prevent command injection
  if (!is_safe_shell_path(binary_path)) {
    std::cerr << "[CoverageSymbolizer] WARNING: Rejecting unsafe path for readelf: " << binary_path << std::endl;
    module_is_dyn_cache_[binary_path] = false;
    return false;
  }
  std::stringstream ss;
  ss << "readelf -h " << shell_escape_path(binary_path) << " 2>/dev/null | grep 'Type:'";
  std::string command = ss.str();
  std::array<char, 512> buffer{};
  std::string line;
  // Execute the readelf command
  FILE *pipe = popen(command.c_str(), "r");
  if (pipe) {
    // Read the first line (ELF type)
    if (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
      line = buffer.data();
      // Remove trailing newline
      if (!line.empty() && line.back() == '\n') {
        line.pop_back();
      }
    }
    pclose(pipe);
  }
  // Check if the ELF type is DYN (shared object)
  bool is_dyn = (line.find("DYN") != std::string::npos);
  module_is_dyn_cache_[binary_path] = is_dyn;
  return is_dyn;
}

// Helper to parse addr2line output (function name and file:line) from a file handle
// Returns true if function name was successfully read, false otherwise
// Reads function name into func_name, and optionally parses file:line into src_file and src_line
bool CoverageSymbolizer::parse_addr2line_output(FILE* pipe, std::array<char, 2048>& buffer,
                                                std::string& func_name,
                                                std::string* src_file,
                                                uint32_t* src_line) {
  if (!pipe) {
    return false;
  }
  
  // Read function name (first line)
  if (fgets(buffer.data(), buffer.size(), pipe) == nullptr) {
    return false;
  }
  
  func_name = buffer.data();
  // Remove trailing newline
  if (!func_name.empty() && func_name.back() == '\n') {
    func_name.pop_back();
  }
  
  // Read file:line (second line) if requested
  if (src_file && src_line) {
    std::string file_line;
    if (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
      file_line = buffer.data();
      // Parse file:line if available
      if (!file_line.empty()) {
        parse_file_colon_line(file_line.c_str(), *src_file, *src_line);
      }
    }
  } else {
    // Skip the second line if not needed
    fgets(buffer.data(), buffer.size(), pipe);
  }
  
  return !func_name.empty() && func_name != "??";
}

// Helper to resolve a symbol name using addr2line
std::string CoverageSymbolizer::resolve_symbol_with_addr2line(uintptr_t pc,
                                          const std::string &binary_path) {
  std::stringstream ss;
  // NOTE: Unset LD_PRELOAD to prevent the metrics bridge library from interfering
  ss << "env -u LD_PRELOAD addr2line -f -C -e " << shell_escape_path(binary_path) << " 0x" << std::hex << pc;
  std::string command = ss.str();

  std::array<char, 2048> buffer{};
  std::string func_name;

  // Execute the addr2line command
  FILE *pipe = popen(command.c_str(), "r");
  bool success = parse_addr2line_output(pipe, buffer, func_name, nullptr, nullptr);
  if (pipe) {
    pclose(pipe);
  }

  if (!success) {
    return "unknown";
  }
  
  return func_name;
}

// Helper to batch resolve symbols efficiently for multiple PCs
void CoverageSymbolizer::batch_resolve_symbols(const std::vector<uintptr_t> &pcs) {
  // Early return if no PCs to resolve
  if (pcs.empty()) {
    return;
  }

  // Group unresolved PCs by module
  struct PcInfo {
    uintptr_t pc;
    uintptr_t rel_pc;
  };
  std::unordered_map<std::string, std::vector<PcInfo>> module_to_pcs;

  for (uintptr_t pc : pcs) {
    if (symbol_cache_.find(pc) != symbol_cache_.end() &&
        pc_loc_cache_.find(pc) != pc_loc_cache_.end()) {
          continue; // already resolved => skip
        }
    Dl_info info{};
    if (!dladdr(reinterpret_cast<void *>(pc), &info) || !info.dli_fname) {
      continue; // no module info => skip
    }
    if (!is_module_allowed_for_logging(info.dli_fname)) {
      continue; // skip non-target modules
    }
    uintptr_t rel_pc = pc;
    if (info.dli_fbase && module_is_dyn(info.dli_fname)) {
      // Adjust relative PC if base address is available and module is dynamic
      rel_pc = pc - reinterpret_cast<uintptr_t>(info.dli_fbase);
    }
    module_to_pcs[info.dli_fname].push_back({pc, rel_pc});
  }

  // Process each module separately
  for (auto &kv : module_to_pcs) {
    // Get module path and list of PCs to resolve
    const std::string &module_path = kv.first;
    auto &vec = kv.second;
    if (vec.empty()) {
      continue; // no PCs to resolve => skip
    }

#if defined(SOLFUZZ_USE_LLVM_SYMBOLIZER)
    auto &Sym = get_llvm_symbolizer();
    for (const auto &p : vec) {
      llvm::object::SectionedAddress SAddr{static_cast<uint64_t>(p.rel_pc), 0u};
      // Prefer inlined info when available
      llvm::Expected<llvm::DIInliningInfo> ResInl =
          Sym.symbolizeInlinedCode(module_path, SAddr);
      if (ResInl) {
        const auto &Inl = ResInl.get();
        const size_t n = Inl.getNumberOfFrames();
        PcLocation loc;
        if (n > 0) {
          // Collect all frames (Frame 0 is the outermost frame)
          for (size_t i = 0; i < n; ++i) {
            const auto &Fi = Inl.getFrame(i);
            PcLocation::FrameLocation fl;
            fl.func = demangle_rust_like(to_str(Fi.FunctionName));
            fl.file = normalize_path(to_str(Fi.FileName));
            fl.line = Fi.Line;
            fl.module = module_path;
            loc.frames.push_back(std::move(fl));
          }
          // Use outermost frame for symbol cache
          const auto &F0 = Inl.getFrame(0);
          std::string func0 = demangle_rust_like(to_str(F0.FunctionName));
          if (!func0.empty())
            symbol_cache_[p.pc] = func0 + " (" + module_path + ")";
          else {
            std::stringstream ss;
            ss << "0x" << std::hex << p.pc;
            symbol_cache_[p.pc] = ss.str();
          }
        }
        pc_loc_cache_[p.pc] = std::move(loc);
        continue;
      }
      // Fallback to single-frame resolution when inlined info is not available
      llvm::Expected<llvm::DILineInfo> Res =
          Sym.symbolizeCode(module_path, SAddr);
      if (Res) {
        const auto &Info = Res.get();
        // Get function name and file name
        std::string func_name =
            demangle_rust_like(std::string(Info.FunctionName));
        std::string file_name = std::string(Info.FileName);
        uint32_t line_no = Info.Line;
        if (!func_name.empty())
          symbol_cache_[p.pc] = func_name + " (" + module_path + ")";
        else {
          std::stringstream ss;
          ss << "0x" << std::hex << p.pc;
          symbol_cache_[p.pc] = ss.str();
        }
        // If file name and line number are available, add to location cache
        if (!file_name.empty() && line_no > 0) {
          PcLocation loc;
          PcLocation::FrameLocation fl;
          fl.file = normalize_path(file_name);
          fl.line = line_no;
          fl.func = func_name;
          fl.module = module_path;
          loc.frames.push_back(fl);
          // Cache the location
          pc_loc_cache_[p.pc] = std::move(loc);
        }
        continue;
      }
      // Fallback when symbolizer fails
      std::stringstream ss;
      ss << "0x" << std::hex << p.pc;
      symbol_cache_[p.pc] = ss.str();
    }
#else
    // Fallback: spawn one addr2line process per module (2 lines per PC)
    // SECURITY: Validate path before using in shell command
    if (!is_safe_shell_path(module_path)) {
      std::cerr << "[CoverageSymbolizer] WARNING: Rejecting unsafe module path: " << module_path << std::endl;
      for (const auto &p : vec) {
        std::stringstream ss;
        ss << "0x" << std::hex << p.pc;
        symbol_cache_[p.pc] = ss.str();
      }
      continue;
    }
    
    std::stringstream cmd;
    // NOTE: Unset LD_PRELOAD to prevent the metrics bridge library from interfering
    cmd << "env -u LD_PRELOAD addr2line -f -C -e " << shell_escape_path(module_path);
    for (const auto &p : vec) {
      cmd << " 0x" << std::hex << p.rel_pc;
    }
    std::string command = cmd.str();
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
      continue; // failed to open pipe => skip
    }
    std::array<char, 2048> buffer{};
    for (const auto &p : vec) {
      std::string func_name;
      std::string src_file;
      uint32_t src_line = 0;

      // Parse addr2line output (function name and file:line)
      if (!parse_addr2line_output(pipe, buffer, func_name, &src_file, &src_line)) {
        // Fallback to hex address if function name not available
        std::stringstream ss;
        ss << "0x" << std::hex << p.pc;
        symbol_cache_[p.pc] = ss.str();
        continue;
      }
      
      // Cache the symbol name
      std::string pretty_name = demangle_rust_like(func_name);
      symbol_cache_[p.pc] = pretty_name + " (" + module_path + ")";
      
      // Cache the location if file:line was successfully parsed
      if (!src_file.empty() && src_line > 0) {
        PcLocation loc;
        PcLocation::FrameLocation fl;
        fl.file = normalize_path(src_file);
        fl.line = src_line;
        fl.func = std::move(pretty_name);
        fl.module = module_path;
        loc.frames.push_back(fl);
        pc_loc_cache_[p.pc] = std::move(loc);
      }
    }
    // Close the pipe
    pclose(pipe);
#endif
  }
}

std::string CoverageSymbolizer::resolve_symbol(uintptr_t pc) {
  // Check cache first
  auto it = symbol_cache_.find(pc);
  if (it != symbol_cache_.end()) {
    return it->second;
  }

  std::string result;
  Dl_info info;

  if (dladdr(reinterpret_cast<void *>(pc), &info) && info.dli_sname) {
    // Try to demangle C++ names
    int status = 0;
    char *demangled =
        abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);

    if (status == 0 && demangled) {
      result = demangled;
      free(demangled); // Safe to free after copy
    } else {
      // If demangling failed, demangled should be nullptr, but free it anyway to be safe
      if (demangled) {
        free(demangled);
      }
      result = info.dli_sname;
    }

    // Add source file info if available
    if (info.dli_fname) {
      // Also attempt to pretty-print using LLVM demangler first, then legacy
      // tokens, add source file info to the result
      result =
          demangle_rust_like(result) + " (" + std::string(info.dli_fname) + ")";
    }
  } else if (dladdr(reinterpret_cast<void *>(pc), &info) && info.dli_fname) {
    // Use addr2line on the correct binary/library
    uintptr_t rel_pc = pc;
    if (info.dli_fbase && module_is_dyn(info.dli_fname)) {
      rel_pc = pc - reinterpret_cast<uintptr_t>(info.dli_fbase);
    }
    std::string addr2line_result =
        resolve_symbol_with_addr2line(rel_pc, info.dli_fname);
    if (addr2line_result != "unknown") {
      // Cache the resolved symbol name with module path
      result = addr2line_result + " (" + std::string(info.dli_fname) + ")";
    } else {
      // Fallback to hex address
      std::stringstream ss;
      ss << "0x" << std::hex << pc;
      result = ss.str();
    }
  } else {
    // Final fallback to hex address
    std::stringstream ss;
    ss << "0x" << std::hex << pc;
    result = ss.str();
  }

  // Cache the resolved symbol name
  symbol_cache_[pc] = result;
  return result;
}

bool CoverageSymbolizer::get_pc_location(uintptr_t pc, PcLocation &loc) {
  auto it = pc_loc_cache_.find(pc);
  if (it != pc_loc_cache_.end()) {
    loc = it->second;
    return true;
  }
  return false; // not found => return false
}

bool CoverageSymbolizer::get_pc_location_for_module(const std::string& module_path,
                                                     uintptr_t rel_pc,
                                                     PcLocation& loc) {
  auto mod_it = module_pc_loc_cache_.find(module_path);
  if (mod_it != module_pc_loc_cache_.end()) {
    auto it = mod_it->second.find(rel_pc);
    if (it != mod_it->second.end()) {
      loc = it->second;
      return true;
    }
  }
  return false;
}

// Batch resolve symbols for a specific module using relative PCs
// This is designed for cross-process symbolization where PCs are offsets
// from the module base, not runtime addresses in our process.
void CoverageSymbolizer::batch_resolve_for_module(
    const std::string& module_path,
    const std::vector<std::pair<uintptr_t, uintptr_t>>& rel_pcs_and_flags) {
  
  SYM_DEBUG("[CoverageSymbolizer] batch_resolve_for_module called: module=" 
            << module_path << ", pcs=" << rel_pcs_and_flags.size() << std::endl);
  
  if (rel_pcs_and_flags.empty() || module_path.empty()) {
    SYM_DEBUG("[CoverageSymbolizer] Early return: empty input" << std::endl);
    return;
  }
  
  // Resolve relative path to absolute path for symbolization
  std::string abs_module_path = module_path;
  char resolved[PATH_MAX];
  if (realpath(module_path.c_str(), resolved)) {
    abs_module_path = resolved;
    SYM_DEBUG("[CoverageSymbolizer] Resolved path: " << abs_module_path << std::endl);
  } else {
    int err = errno;
    // Only log error once per path to avoid spam
    static std::unordered_set<std::string> logged_errors;
    if (logged_errors.find(module_path) == logged_errors.end()) {
      std::cerr << "[CoverageSymbolizer] ERROR: realpath failed for '" << module_path 
                << "': " << strerror(err) << " (errno=" << err << ")" << std::endl;
      logged_errors.insert(module_path);
    }
    // Continue with original path - might still work
  }
  
  // Filter out already-resolved PCs (check per-module cache)
  auto& mod_sym = module_symbol_cache_[abs_module_path];
  auto& mod_loc = module_pc_loc_cache_[abs_module_path];
  std::vector<std::pair<uintptr_t, uintptr_t>> to_resolve;
  for (const auto& p : rel_pcs_and_flags) {
    uintptr_t rel_pc = p.first;
    if (mod_sym.find(rel_pc) == mod_sym.end()) {
      to_resolve.push_back(p);
    }
  }
  
  SYM_DEBUG("[CoverageSymbolizer] Need to resolve: " << to_resolve.size() << " PCs" << std::endl);
  
  if (to_resolve.empty()) {
    SYM_DEBUG("[CoverageSymbolizer] Early return: all already cached" << std::endl);
    return;
  }
  
#if defined(SOLFUZZ_USE_LLVM_SYMBOLIZER)
  // Use LLVM symbolizer if available
  SYM_DEBUG("[CoverageSymbolizer] Using LLVM symbolizer for " << abs_module_path << std::endl);
  auto& Sym = get_llvm_symbolizer();
  size_t success_count = 0, fail_count = 0;
  
  // Try first PC as a test (only when debug enabled)
  if (symbolizer_debug_enabled() && !to_resolve.empty()) {
    uintptr_t test_pc = to_resolve[0].first;
    std::cerr << "[CoverageSymbolizer] Test symbolize PC 0x" << std::hex << test_pc << std::dec << std::endl;
    try {
      llvm::object::SectionedAddress TestAddr{static_cast<uint64_t>(test_pc), 0u};
      llvm::Expected<llvm::DIInliningInfo> TestRes = Sym.symbolizeInlinedCode(abs_module_path, TestAddr);
      if (TestRes) {
        const auto& TestInl = TestRes.get();
        size_t frames = TestInl.getNumberOfFrames();
        std::cerr << "[CoverageSymbolizer] Test result: " << frames << " frames" << std::endl;
        if (frames > 0) {
          const auto& F = TestInl.getFrame(0);
          std::cerr << "[CoverageSymbolizer] Frame 0: " << F.FunctionName << " @ " << F.FileName << ":" << F.Line << std::endl;
        }
      } else {
        llvm::consumeError(TestRes.takeError());
        std::cerr << "[CoverageSymbolizer] Test symbolize FAILED" << std::endl;
      }
    } catch (const std::exception& e) {
      std::cerr << "[CoverageSymbolizer] Test exception: " << e.what() << std::endl;
    }
  }
  
  for (const auto& p : to_resolve) {
    uintptr_t rel_pc = p.first;
    llvm::object::SectionedAddress SAddr{static_cast<uint64_t>(rel_pc), 0u};
    
    llvm::Expected<llvm::DIInliningInfo> ResInl =
        Sym.symbolizeInlinedCode(abs_module_path, SAddr);
    if (ResInl) {
      const auto& Inl = ResInl.get();
      const size_t n = Inl.getNumberOfFrames();
      PcLocation loc;
      if (n > 0) {
        for (size_t i = 0; i < n; ++i) {
          const auto& Fi = Inl.getFrame(i);
          PcLocation::FrameLocation fl;
          fl.func = demangle_rust_like(trim_copy(to_str(Fi.FunctionName)));
          fl.file = normalize_path(trim_copy(to_str(Fi.FileName)));
          fl.line = Fi.Line;
          fl.module = abs_module_path;
          loc.frames.push_back(std::move(fl));
        }
        const auto& F0 = Inl.getFrame(0);
        std::string func0 = demangle_rust_like(trim_copy(to_str(F0.FunctionName)));
        if (!func0.empty()) {
          mod_sym[rel_pc] = func0 + " (" + abs_module_path + ")";
          success_count++;
        } else {
          std::stringstream ss;
          ss << "0x" << std::hex << rel_pc;
          mod_sym[rel_pc] = ss.str();
          fail_count++;
        }
        mod_loc[rel_pc] = std::move(loc);
      } else {
        // No frames - use hex address
        std::stringstream ss;
        ss << "0x" << std::hex << rel_pc;
        mod_sym[rel_pc] = ss.str();
        fail_count++;
      }
    } else {
      llvm::consumeError(ResInl.takeError());
      std::stringstream ss;
      ss << "0x" << std::hex << rel_pc;
      mod_sym[rel_pc] = ss.str();
      fail_count++;
    }
  }
  // Debug output (only first time)
  static bool first_batch = true;
  if (first_batch) {
    std::cerr << "[CoverageSymbolizer] LLVM symbolizer: " << success_count << " success, " 
              << fail_count << " fail for " << abs_module_path << std::endl;
    first_batch = false;
  }
#else
  // Fallback: Use addr2line batch mode
  // NOTE: Command line has limited length, so we batch the calls
  // NOTE: Unset LD_PRELOAD to prevent the metrics bridge library from being loaded
  // into addr2line (which causes it to fail/hang due to static initialization)
  SYM_DEBUG("[CoverageSymbolizer] Using addr2line for " << abs_module_path << " (" << to_resolve.size() << " PCs)" << std::endl);
  
  // Batch size - keep command line under ~100KB (addr is ~12 chars, so ~8000 per batch)
  const size_t BATCH_SIZE = 4000;
  size_t processed = 0;
  size_t success_count = 0;
  
  while (processed < to_resolve.size()) {
    size_t batch_end = std::min(processed + BATCH_SIZE, to_resolve.size());
    
    // SECURITY: Validate module path to prevent command injection
    // Module paths should only contain alphanumeric, dots, underscores, hyphens, and slashes
    bool path_safe = true;
    for (char c : abs_module_path) {
      if (!std::isalnum(c) && c != '.' && c != '_' && c != '-' && c != '/' && c != '+') {
        path_safe = false;
        break;
      }
    }
    if (!path_safe || abs_module_path.empty() || abs_module_path.find("..") != std::string::npos) {
      std::cerr << "[CoverageSymbolizer] ERROR: Rejecting unsafe module path: " << abs_module_path << std::endl;
      for (size_t i = processed; i < batch_end; i++) {
        std::stringstream ss;
        ss << "0x" << std::hex << to_resolve[i].first;
        mod_sym[to_resolve[i].first] = ss.str();
      }
      processed = batch_end;
      continue;
    }
    
    std::stringstream cmd;
    // Use shell_escape_path for proper escaping
    cmd << "env -u LD_PRELOAD addr2line -f -C -e " << shell_escape_path(abs_module_path);
    for (size_t i = processed; i < batch_end; i++) {
      cmd << " 0x" << std::hex << to_resolve[i].first;
    }
    
    FILE* pipe = popen(cmd.str().c_str(), "r");
    if (!pipe) {
      int err = errno;
      std::cerr << "[CoverageSymbolizer] ERROR: popen failed for batch starting at " << processed 
                << ": " << strerror(err) << " (errno=" << err << ")" << std::endl;
      std::cerr << "[CoverageSymbolizer] Command was: " << cmd.str().substr(0, 200) << "..." << std::endl;
      // Fallback to hex addresses for this batch
      for (size_t i = processed; i < batch_end; i++) {
        std::stringstream ss;
        ss << "0x" << std::hex << to_resolve[i].first;
        mod_sym[to_resolve[i].first] = ss.str();
      }
      processed = batch_end;
      continue;
    }
    
    // Parse addr2line output (alternating function name and source location)
    char buffer[4096];
    size_t idx = processed;
    while (idx < batch_end && fgets(buffer, sizeof(buffer), pipe)) {
      std::string func_line = trim_copy(buffer);
      std::string src_line;
      if (fgets(buffer, sizeof(buffer), pipe)) {
        src_line = trim_copy(buffer);
      }
      
      uintptr_t rel_pc = to_resolve[idx].first;
      
      // Parse function name
      std::string func_name = func_line;
      if (func_name.empty() || func_name == "??" || func_name == "??()") {
        std::stringstream ss;
        ss << "0x" << std::hex << rel_pc;
        func_name = ss.str();
      } else {
        func_name = demangle_rust_like(func_name);
        success_count++;
      }
      
      // Parse source location
      PcLocation loc;
      PcLocation::FrameLocation fl;
      fl.func = func_name;
      fl.module = abs_module_path;
      
      if (!src_line.empty() && src_line != "??:0" && src_line != "??:?") {
        // Parse "filename:line" format
        size_t colon_pos = src_line.rfind(':');
        if (colon_pos != std::string::npos) {
          fl.file = normalize_path(src_line.substr(0, colon_pos));
          try {
            fl.line = static_cast<uint32_t>(std::stoul(src_line.substr(colon_pos + 1)));
          } catch (...) {
            fl.line = 0;
          }
        }
      }
      
      loc.frames.push_back(fl);
      mod_loc[rel_pc] = loc;
      mod_sym[rel_pc] = func_name + " (" + abs_module_path + ")";
      
      idx++;
    }
    
    int pclose_status = pclose(pipe);
    if (pclose_status != 0) {
      if (WIFEXITED(pclose_status)) {
        int exit_code = WEXITSTATUS(pclose_status);
        if (exit_code != 0) {
          std::cerr << "[CoverageSymbolizer] WARNING: addr2line exited with code " << exit_code 
                    << " for batch " << processed << "-" << batch_end << std::endl;
        }
      } else if (WIFSIGNALED(pclose_status)) {
        std::cerr << "[CoverageSymbolizer] WARNING: addr2line killed by signal " 
                  << WTERMSIG(pclose_status) << " for batch " << processed << "-" << batch_end << std::endl;
      }
    }
    
    // Fill in any remaining entries in this batch with hex addresses
    size_t missing = batch_end - idx;
    if (missing > 0) {
      std::cerr << "[CoverageSymbolizer] WARNING: addr2line returned fewer results than expected, "
                << missing << " PCs missing in batch " << processed << "-" << batch_end << std::endl;
    }
    for (; idx < batch_end; idx++) {
      uintptr_t rel_pc = to_resolve[idx].first;
      std::stringstream ss;
      ss << "0x" << std::hex << rel_pc;
      mod_sym[rel_pc] = ss.str();
    }
    
    processed = batch_end;
  }
  
  std::cerr << "[CoverageSymbolizer] addr2line resolved " << success_count << "/" << to_resolve.size() << " symbols" << std::endl;
#endif
}

} // namespace sol_compat

