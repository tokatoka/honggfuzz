#include "jsonl_writer.h"

#include <iostream>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <filesystem>

namespace sol_compat {

bool JsonlSink::open(const std::string& path) {
    // Ensure parent directory exists (if any).
    const std::filesystem::path parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) {
        try {
            std::filesystem::create_directories(parent);
        } catch (const std::exception& e) {
            std::cerr << "[JsonlSink] WARNING: Failed to create directory for "
                      << path << ": " << e.what() << std::endl;
            // Continue anyway — the directory might already exist.
        }
    }

    // Close any previously-open descriptor (guard against double-open).
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    int new_fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (new_fd < 0) {
        std::cerr << "[JsonlSink] ERROR: Failed to open " << path
                  << ": " << std::strerror(errno) << std::endl;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mu_);
        fd_ = new_fd;
    }
    path_ = path;
    std::cerr << "[JsonlSink] Opened " << path << " for JSONL output" << std::endl;
    return true;
}

void JsonlSink::write(const std::string& line) {
    if (fd_ < 0) return;

    // O_APPEND positions the file offset atomically before each write(2).
    // Combined with the mutex and a single write(2) call, this keeps
    // lines intact when multiple threads or processes share the file.
    std::lock_guard<std::mutex> lock(mu_);
    if (fd_ < 0) return;

    ssize_t written;
    do {
        written = ::write(fd_, line.data(), line.size());
    } while (written < 0 && errno == EINTR);

    if (written < 0) {
        std::cerr << "[JsonlSink] ERROR: write failed: "
                  << std::strerror(errno) << std::endl;
    } else if (static_cast<size_t>(written) != line.size()) {
        std::cerr << "[JsonlSink] ERROR: short write: " << written
                  << " of " << line.size() << " bytes" << std::endl;
    }
}

void JsonlSink::close() {
    std::lock_guard<std::mutex> lock(mu_);
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
        std::cerr << "[JsonlSink] Closed " << path_ << std::endl;
    }
}

} // namespace sol_compat
