#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

#include "mmproxy/memory_guard.hpp"

namespace erikslund::mmproxy {
namespace {

constexpr std::uint64_t kLimitBytes = 1000;

// Stand in for a cgroup file such as memory.current, and delete it when the test ends.
class CgroupFile {
public:
    explicit CgroupFile(std::string_view name, std::string_view content)
        : path_(std::filesystem::temp_directory_path() / ("mmproxy-test-" + std::string(name))) {
        write(content);
    }
    ~CgroupFile() { std::filesystem::remove(path_); }
    CgroupFile(const CgroupFile&) = delete;
    CgroupFile& operator=(const CgroupFile&) = delete;

    void write(std::string_view content) const { std::ofstream(path_, std::ios::trunc) << content; }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

TEST_CASE("A cgroup memory.max reads as bytes, and max means no limit") {
    CHECK(parse_memory_max("536870912") == 536870912);
    CHECK_FALSE(parse_memory_max("max").has_value());
    CHECK_FALSE(parse_memory_max("").has_value());
    CHECK_FALSE(parse_memory_max("0").has_value());
    CHECK_FALSE(parse_memory_max("512M").has_value());
}

TEST_CASE("memory.stat yields its page-cache line") {
    CHECK(parse_file_cache_bytes("anon 4096\nfile 8192\nkernel 1\n") == 8192);
    CHECK(parse_file_cache_bytes("file 5\n") == 5);
    CHECK_FALSE(parse_file_cache_bytes("anon 1\nfile_mapped 2\n").has_value());
    CHECK_FALSE(parse_file_cache_bytes("").has_value());
}

TEST_CASE("The memory guard reports pressure from 80% of the limit") {
    const CgroupFile usage("memory.current", "0\n");
    const CgroupFile stat("memory.stat", "anon 0\nfile 0\n");
    const MemoryGuard guard(
        MemoryLimit{.bytes = kLimitBytes, .usage_path = usage.path(), .stat_path = stat.path()});
    REQUIRE(guard.enabled());
    CHECK(guard.threshold_bytes() == 800);
    CHECK_FALSE(guard.under_pressure());
    usage.write("799\n");
    CHECK_FALSE(guard.under_pressure());
    usage.write("800\n");
    CHECK(guard.under_pressure());
}

TEST_CASE("Page cache the kernel can reclaim does not count as pressure") {
    const CgroupFile usage("memory.current", "900\n");
    const CgroupFile stat("memory.stat", "anon 100\nfile 200\n");
    const MemoryGuard guard(
        MemoryLimit{.bytes = kLimitBytes, .usage_path = usage.path(), .stat_path = stat.path()});
    CHECK_FALSE(guard.under_pressure());
    stat.write("anon 800\nfile 50\n");
    CHECK(guard.under_pressure());
}

TEST_CASE("Without a usable cgroup limit the memory guard stays off") {
    const MemoryGuard off;
    CHECK_FALSE(off.enabled());
    CHECK_FALSE(off.under_pressure());
    const MemoryGuard missing(MemoryLimit{.bytes = kLimitBytes,
                                          .usage_path = "/nonexistent/memory.current",
                                          .stat_path = "/nonexistent/memory.stat",
                                          .from_parent_cgroup = false});
    CHECK_FALSE(missing.enabled());
    CHECK_FALSE(missing.under_pressure());
}

} // namespace
} // namespace erikslund::mmproxy
