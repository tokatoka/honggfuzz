#include <climits>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <unistd.h>

#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

extern "C" int hfuzz_write_coverage_required_json(
    const char* path, const char* const* files, size_t count) {
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> w(sb);

    w.StartObject();
    w.Key("coverage_required_files");
    w.StartArray();
    for (size_t i = 0; i < count; i++) {
        if (!files[i]) continue;
        w.String(files[i]);
    }
    w.EndArray();
    w.EndObject();

    /* Atomic write: temp file + rename */
    char tmp_path[PATH_MAX];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", path, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) return -1;

    FILE* fp = fopen(tmp_path, "w");
    if (!fp) return -1;
    size_t written = fwrite(sb.GetString(), 1, sb.GetSize(), fp);
    if (fputc('\n', fp) == EOF || fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    if (fclose(fp) != 0) {
        unlink(tmp_path);
        return -1;
    }
    if (written != sb.GetSize()) {
        unlink(tmp_path);
        return -1;
    }
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}
