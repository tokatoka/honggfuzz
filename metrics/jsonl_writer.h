#pragma once

#include <cstdio>
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <chrono>

#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

namespace sol_compat {

// Thin wrapper around RapidJSON Writer for JSONL output.
// Each instance produces one JSON object; call finish() to get the
// serialized line (with trailing newline).
class JsonBuilder {
public:
    JsonBuilder() : w_(sb_) { w_.StartObject(); }

    void add(const char* key, const std::string& val) {
        w_.Key(key); w_.String(val.data(), static_cast<rapidjson::SizeType>(val.size()));
    }

    void add(const char* key, uint32_t val) {
        w_.Key(key); w_.Uint(val);
    }

    void add(const char* key, uint64_t val) {
        w_.Key(key); w_.Uint64(val);
    }

    void add(const char* key, int val) {
        w_.Key(key); w_.Int(val);
    }

    void add(const char* key, float val) {
        w_.Key(key); w_.Double(static_cast<double>(val));
    }

    void add(const char* key, double val) {
        w_.Key(key); w_.Double(val);
    }

    // ISO 8601 timestamp from epoch milliseconds
    void add_timestamp(const char* key, int64_t epoch_ms) {
        time_t secs = static_cast<time_t>(epoch_ms / 1000);
        int millis = static_cast<int>(epoch_ms % 1000);
        struct tm tm_buf;
        gmtime_r(&secs, &tm_buf);
        char tmp[80];
        snprintf(tmp, sizeof(tmp), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                 tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);
        w_.Key(key); w_.String(tmp);
    }

    void add_string_array(const char* key, const std::vector<std::string>& vals) {
        w_.Key(key);
        w_.StartArray();
        for (const auto& v : vals) {
            w_.String(v.data(), static_cast<rapidjson::SizeType>(v.size()));
        }
        w_.EndArray();
    }

    void add_uint32_array(const char* key, const std::vector<uint32_t>& vals) {
        w_.Key(key);
        w_.StartArray();
        for (uint32_t v : vals) {
            w_.Uint(v);
        }
        w_.EndArray();
    }

    // Finalize and return the JSON line (with trailing newline).
    std::string finish() {
        w_.EndObject();
        std::string result(sb_.GetString(), sb_.GetSize());
        result += '\n';
        return result;
    }

private:
    rapidjson::StringBuffer sb_;
    rapidjson::Writer<rapidjson::StringBuffer> w_;
};

// Thread-safe (single-process) append-only JSONL file writer.
// Opened with O_APPEND.  The mutex serializes writes across threads
// within one process; cross-process atomicity relies on each write
// fitting in a single write(2) call (typically true for our 1-3 KB
// lines, but not formally guaranteed for regular files like it is
// for pipes).  In practice each job writes its own file, so
// cross-process interleaving is not an issue.
class JsonlSink {
public:
    bool open(const std::string& path);
    void write(const std::string& line);  // must end with '\n'
    void close();

    bool is_open() const { return fd_ >= 0; }
    const std::string& path() const { return path_; }

private:
    int fd_ = -1;
    std::string path_;
    std::mutex mu_;
};

// Helper: current epoch milliseconds.
inline int64_t now_epoch_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

} // namespace sol_compat
