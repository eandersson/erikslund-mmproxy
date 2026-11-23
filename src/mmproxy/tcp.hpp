#pragma once
// Run one nonblocking TCP listener and its connection shard.

#include <cstddef>
#include <stop_token>

#include "mmproxy/balancer.hpp"
#include "mmproxy/fair_share.hpp"
#include "mmproxy/memory_guard.hpp"
#include "mmproxy/metrics.hpp"
#include "mmproxy/socket.hpp"

namespace erikslund::mmproxy {

// State every TCP worker shares. main owns it and keeps it alive until the workers stop.
struct TcpShared {
    Balancer& balancer;
    FairShare& fair_share;
    const MemoryGuard& memory;
};

void run_tcp(const std::stop_token& stop, const Config& config, FileDescriptor listener,
             std::size_t connection_limit, Metrics& metrics, const TcpShared& shared,
             std::size_t worker_index);

} // namespace erikslund::mmproxy
