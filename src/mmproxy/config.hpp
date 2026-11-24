#pragma once
// Startup configuration for one proxy listener and its loopback backends.

#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>

#include "mmproxy/address.hpp"

namespace erikslund::mmproxy {

enum class Transport { Tcp, Udp };

inline constexpr std::size_t kDescriptorsPerTcpConnection = 6;
inline constexpr std::size_t kDescriptorsPerUdpFlow = 1;
inline constexpr std::size_t kCachedPipesPerWorker = 8;
inline constexpr std::size_t kStreamingPipeBytes = 1 << 20;

class ConfigError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Config {
    Endpoint listen;
    std::optional<Endpoint> backend_ipv4;
    std::optional<Endpoint> backend_ipv6;
    TrustList trusted;
    Transport transport = Transport::Tcp;
    std::size_t workers = 1;
    std::size_t max_connections = 65'536;
    std::chrono::milliseconds header_timeout{2000};
    std::chrono::milliseconds connect_timeout{3000};
    std::chrono::milliseconds idle_timeout{300'000}; // 0 disables the TCP idle deadline.
    std::chrono::milliseconds udp_timeout{60'000};
    std::chrono::milliseconds user_timeout{0}; // 0 keeps the kernel's retransmission limit.
    int backend_mark = 0;
    std::size_t max_header_bytes = 4096;
    bool allow_local_relays = false;
    bool allow_any_relay = false;
    std::size_t streaming_pipe_budget = 1;
};

[[nodiscard]] Config parse_config(std::span<char*> arguments);
[[nodiscard]] const std::optional<Endpoint>& backend_for(const Config& config, int family);
[[nodiscard]] std::size_t worker_share(std::size_t total, std::size_t workers,
                                       std::size_t worker_index) noexcept;
[[nodiscard]] std::string_view usage();

} // namespace erikslund::mmproxy
