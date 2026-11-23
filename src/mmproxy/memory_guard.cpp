#include "mmproxy/memory_guard.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <unistd.h>

#include "mmproxy/cgroup.hpp"

namespace erikslund::mmproxy {
namespace {

constexpr std::string_view kNoLimit = "max";
constexpr std::string_view kFileKey = "file ";
constexpr std::uint64_t kPressurePercent = 80;
constexpr std::uint64_t kPercent = 100;
constexpr std::size_t kUsageTextBytes = 32;
constexpr std::size_t kStatTextBytes = 8192;

std::optional<std::uint64_t> parse_count(std::string_view text) noexcept {
    std::uint64_t count = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), count);
    if (parsed.ec != std::errc{} || parsed.ptr == text.data())
        return std::nullopt;
    return count;
}

template <std::size_t Size>
std::string_view read_file(const FileDescriptor& file, std::array<char, Size>& buffer) noexcept {
    if (!file)
        return {};
    const auto length = ::pread(file.get(), buffer.data(), buffer.size(), 0);
    return length > 0 ? std::string_view(buffer.data(), static_cast<std::size_t>(length)) :
                        std::string_view{};
}

} // namespace

std::optional<std::uint64_t> parse_memory_max(std::string_view text) noexcept {
    if (text == kNoLimit)
        return std::nullopt;
    std::uint64_t bytes = 0;
    const auto [end, error] = std::from_chars(text.begin(), text.end(), bytes);
    if (error != std::errc{} || end != text.end() || bytes == 0)
        return std::nullopt;
    return bytes;
}

std::optional<std::uint64_t> parse_file_pages(std::string_view stat) noexcept {
    std::size_t start = 0;
    while (start < stat.size()) {
        const auto end = std::min(stat.find('\n', start), stat.size());
        const auto line = stat.substr(start, end - start);
        if (line.starts_with(kFileKey))
            return parse_count(line.substr(kFileKey.size()));
        start = end + 1;
    }
    return std::nullopt;
}

std::optional<MemoryLimit> find_memory_limit() {
    const auto directories = cgroup_directories();
    std::optional<MemoryLimit> tightest;
    for (const auto& directory : directories) {
        std::ifstream file(directory / "memory.max");
        std::string text;
        if (!(file >> text))
            continue;
        const auto bytes = parse_memory_max(text);
        if (bytes && (!tightest || *bytes < tightest->bytes))
            tightest = MemoryLimit{.bytes = *bytes,
                                   .usage = directory / "memory.current",
                                   .stat = directory / "memory.stat",
                                   .shared = directory != directories.front()};
    }
    return tightest;
}

MemoryGuard::MemoryGuard(const MemoryLimit& limit)
    : usage_(::open(limit.usage.c_str(), O_RDONLY | O_CLOEXEC)),
      stat_(::open(limit.stat.c_str(), O_RDONLY | O_CLOEXEC)),
      threshold_bytes_(limit.bytes / kPercent * kPressurePercent) {}

bool MemoryGuard::enabled() const noexcept {
    return static_cast<bool>(usage_);
}

std::uint64_t MemoryGuard::threshold_bytes() const noexcept {
    return threshold_bytes_;
}

bool MemoryGuard::under_pressure() const noexcept {
    std::array<char, kUsageTextBytes> usage_text{};
    const auto used = parse_count(read_file(usage_, usage_text));
    if (!used || *used < threshold_bytes_)
        return false;
    std::array<char, kStatTextBytes> stat_text{};
    const auto cache = parse_file_pages(read_file(stat_, stat_text)).value_or(0);
    return *used - std::min(*used, cache) >= threshold_bytes_;
}

} // namespace erikslund::mmproxy
