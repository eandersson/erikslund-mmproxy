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

enum class TimeoutPhase : std::uint8_t { Header, Idle };
inline constexpr std::size_t kTimeoutPhaseCount = 2;
static_assert(static_cast<std::size_t>(TimeoutPhase::Idle) + 1 == kTimeoutPhaseCount);

inline void increment(std::atomic_uint64_t& counter, std::uint64_t amount = 1) noexcept {
    counter.fetch_add(amount, std::memory_order_relaxed);
}

struct alignas(64) Metrics {
    std::atomic_uint64_t active{0};
    std::atomic_uint64_t accepted{0};
    std::atomic_uint64_t untrusted{0};
    std::atomic_uint64_t closed_before_header{0};
    std::atomic_uint64_t invalid_header{0};
    std::atomic_uint64_t limit_reached{0};
    std::atomic_uint64_t memory_shed{0};
    std::atomic_uint64_t share_refused{0};
    std::atomic_uint64_t flows_evicted{0};
    std::array<std::atomic_uint64_t, kBackendFailureCount> backend_failures{};
    std::array<std::atomic_uint64_t, kTimeoutPhaseCount> timeouts{};
    std::atomic_uint64_t client_to_backend_bytes{0};
    std::atomic_uint64_t backend_to_client_bytes{0};
    std::atomic_uint64_t udp_dropped{0};

    void count_backend_failure(BackendFailure failure) noexcept {
        increment(backend_failures[static_cast<std::size_t>(failure)]);
    }

    void count_timeout(TimeoutPhase phase) noexcept {
        increment(timeouts[static_cast<std::size_t>(phase)]);
    }
};

} // namespace erikslund::mmproxy
