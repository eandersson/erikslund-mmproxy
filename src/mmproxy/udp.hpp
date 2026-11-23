#pragma once
// Forward PROXY v2 datagrams through bounded, worker-owned flows.

#include <cstddef>
#include <stop_token>

#include "mmproxy/config.hpp"
#include "mmproxy/metrics.hpp"
#include "mmproxy/socket.hpp"

namespace erikslund::mmproxy {

void run_udp(const std::stop_token& stop, const Config& config, FileDescriptor listener,
             std::size_t flow_limit, Metrics& metrics);

} // namespace erikslund::mmproxy
