#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace erikslund::mmproxy {

enum class UpstreamFailure : std::uint8_t {
    NoBackend,
    Setup,
    Bind,
    Connect,
    ConnectTimeout,
    Relay,
};
inline constexpr std::size_t kUpstreamFailureCount = 6;
static_assert(static_cast<std::size_t>(UpstreamFailure::Relay) + 1 == kUpstreamFailureCount);

enum class TimeoutPhase : std::uint8_t { Header, Idle };
inline constexpr std::size_t kTimeoutPhaseCount = 2;
static_assert(static_cast<std::size_t>(TimeoutPhase::Idle) + 1 == kTimeoutPhaseCount);

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
    std::array<std::atomic_uint64_t, kUpstreamFailureCount> upstream_errors{};
    std::array<std::atomic_uint64_t, kTimeoutPhaseCount> timeouts{};
    std::atomic_uint64_t client_to_backend_bytes{0};
    std::atomic_uint64_t backend_to_client_bytes{0};
    std::atomic_uint64_t udp_dropped{0};

    void count_upstream_error(UpstreamFailure failure) noexcept {
        upstream_errors[static_cast<std::size_t>(failure)].fetch_add(1, std::memory_order_relaxed);
    }

    void count_timeout(TimeoutPhase phase) noexcept {
        timeouts[static_cast<std::size_t>(phase)].fetch_add(1, std::memory_order_relaxed);
    }
};

} // namespace erikslund::mmproxy
