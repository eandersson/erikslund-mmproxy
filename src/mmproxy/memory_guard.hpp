#pragma once
// Watch the cgroup memory limit, so the proxy closes stalled connections before the kernel's OOM
// killer ends every tunnel at once.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>

#include "mmproxy/file_descriptor.hpp"

namespace erikslund::mmproxy {

struct MemoryLimit {
    std::uint64_t bytes;
    std::filesystem::path usage_path; // that cgroup's memory.current
    std::filesystem::path stat_path;  // that cgroup's memory.stat
    // The limit belongs to a parent cgroup, whose other members' memory also counts.
    bool from_parent_cgroup = false;
};

[[nodiscard]] std::optional<std::uint64_t> parse_memory_max(std::string_view text) noexcept;
[[nodiscard]] std::optional<std::uint64_t> parse_file_cache_bytes(std::string_view stat) noexcept;
[[nodiscard]] std::optional<MemoryLimit> find_memory_limit();

class MemoryGuard {
public:
    MemoryGuard() = default;
    explicit MemoryGuard(const MemoryLimit& limit);

    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] std::uint64_t threshold_bytes() const noexcept;
    [[nodiscard]] bool under_pressure() const noexcept;

private:
    FileDescriptor usage_file_;
    FileDescriptor stat_file_;
    std::uint64_t threshold_bytes_ = 0;
};

} // namespace erikslund::mmproxy
