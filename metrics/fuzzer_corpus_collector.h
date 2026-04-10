#pragma once

#include <cstdint>

namespace sol_compat {

class FuzzerCorpusCollector {
public:
    static void init();
    
    static uint64_t get_corpus_size(); // number of test cases
    static uint64_t get_corpus_size_bytes(); // total size of all test cases
    
    // Returns a [0.0, 100.0] score representing corpus diversity
    static float get_corpus_diversity_score();
    
    static void reset();

private:
    static bool s_initialized;
    static uint64_t s_corpus_size;
    static uint64_t s_corpus_size_bytes;
    
    static constexpr float k_corpus_size_scaling = 2.0f;        // Corpus size to diversity score scaling factor
    
    static void update_corpus_stats();
};

} // namespace sol_compat
