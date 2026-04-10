#include "fuzzer_corpus_collector.h"

#include <cstdlib>
#include <iostream>
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>

namespace sol_compat {

// Static members
bool FuzzerCorpusCollector::s_initialized = false;
uint64_t FuzzerCorpusCollector::s_corpus_size = 0;
uint64_t FuzzerCorpusCollector::s_corpus_size_bytes = 0;

// Helper: Count files in a directory
static uint64_t count_files_in_directory(const std::string& dir_path) {
    uint64_t count = 0;
    DIR* dir = opendir(dir_path.c_str());
    if (!dir) {
        return 0;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG) {  // Regular file
            count++;
        }
    }
    closedir(dir);
    return count;
}

// Helper: Get total size of files in a directory
static uint64_t get_directory_size_bytes(const std::string& dir_path) {
    uint64_t total_size = 0;
    DIR* dir = opendir(dir_path.c_str());
    if (!dir) {
        return 0;
    }

    struct dirent* entry;
    struct stat file_stat;
    std::string full_path;

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG) {  // Regular file
            full_path = dir_path + "/" + entry->d_name;
            if (stat(full_path.c_str(), &file_stat) == 0) {
                total_size += file_stat.st_size;
            }
        }
    }
    closedir(dir);
    return total_size;
}

void FuzzerCorpusCollector::init() {
    if (s_initialized) {
        return;
    }

    s_initialized = true;
    update_corpus_stats();

    std::cerr << "[FuzzerCorpusCollector] Initialized - Corpus size: "
              << s_corpus_size << " inputs, "
              << s_corpus_size_bytes << " bytes" << std::endl;
}

void FuzzerCorpusCollector::update_corpus_stats() {
    // Try to read corpus size from corpus directory
    const char* corpus_dir = std::getenv("CORPUS_DIR");
    if (!corpus_dir) {
        // Try common corpus locations
        const char* possible_dirs[] = {
            "./corpus",
            "./out",
            ".",
            nullptr
        };

        for (int i = 0; possible_dirs[i] != nullptr; i++) {
            struct stat dir_stat;
            if (stat(possible_dirs[i], &dir_stat) == 0 && S_ISDIR(dir_stat.st_mode)) {
                // Check if this looks like a corpus directory
                uint64_t file_count = count_files_in_directory(possible_dirs[i]);
                if (file_count > 0) {
                    corpus_dir = possible_dirs[i];
                    break;
                }
            }
        }
    }

    if (corpus_dir) {
        s_corpus_size = count_files_in_directory(corpus_dir);
        s_corpus_size_bytes = get_directory_size_bytes(corpus_dir);

        std::cerr << "[FuzzerCorpusCollector] Found corpus at: " << corpus_dir
                  << " (" << s_corpus_size << " files, "
                  << s_corpus_size_bytes << " bytes)" << std::endl;
    } else {
        std::cerr << "[FuzzerCorpusCollector] Using tracked corpus stats"
                  << " (" << s_corpus_size << " files, "
                  << s_corpus_size_bytes << " bytes)" << std::endl;
    }
}

uint64_t FuzzerCorpusCollector::get_corpus_size() {
    if (!s_initialized) {
        init();
    }
    // Update stats periodically (rate-limit?)
    update_corpus_stats();
    return s_corpus_size;
}

uint64_t FuzzerCorpusCollector::get_corpus_size_bytes() {
    if (!s_initialized) {
        init();
    }
    // Update stats periodically (rate-limit?)
    update_corpus_stats();
    return s_corpus_size_bytes;
}

float FuzzerCorpusCollector::get_corpus_diversity_score() {
    if (!s_initialized) {
        init();
    }

    uint64_t corpus_size = get_corpus_size();
    if (corpus_size == 0) {
        return 0.0f;
    }

    // Heuristic based on corpus size
    return std::min(100.0f, static_cast<float>(corpus_size) * k_corpus_size_scaling);
}

void FuzzerCorpusCollector::reset() {
    s_initialized = false;
    s_corpus_size = 0;
    s_corpus_size_bytes = 0;
}

} // namespace sol_compat
