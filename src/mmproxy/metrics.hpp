#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace erikslund::mmproxy {

enum class BackendFailure : std::uint8_t {
    NoBackend,
    Setup,
    Bind,
    Connect,
    ConnectTimeout,
    Forwarding,
};
inline constexpr std::size_t kBackendFailureCount = 6;
static_assert(static_cast<std::size_t>(BackendFailure::Forwarding) + 1 == kBackendFailureCount);

inline void increment(std::atomic_uint64_t& counter) noexcept {
    counter.fetch_add(1, std::memory_order_relaxed);
}

struct alignas(64) Metrics {
    std::atomic_uint64_t untrusted{0};
    std::atomic_uint64_t invalid_header{0};
    std::atomic_uint64_t header_timeouts{0};
    std::atomic_uint64_t limit_reached{0};
    std::atomic_uint64_t memory_shed{0};
    std::atomic_uint64_t share_refused{0};
    std::atomic_uint64_t flows_evicted{0};
    std::atomic_uint64_t udp_dropped{0};
    std::array<std::atomic_uint64_t, kBackendFailureCount> backend_failures{};

    void count_backend_failure(BackendFailure failure) noexcept {
        increment(backend_failures[static_cast<std::size_t>(failure)]);
    }
};

} // namespace erikslund::mmproxy
