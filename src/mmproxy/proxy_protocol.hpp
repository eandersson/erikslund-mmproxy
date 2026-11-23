#pragma once
// Decode one PROXY header from a stream prefix or a complete datagram.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <span>

#include "mmproxy/address.hpp"

namespace erikslund::mmproxy {

inline constexpr std::size_t kMaxProxyV1HeaderSize = 107;
inline constexpr std::size_t kProxyV2FixedHeaderSize = 16;
inline constexpr std::size_t kMaxProxyHeaderSize =
    kProxyV2FixedHeaderSize + std::numeric_limits<std::uint16_t>::max();

enum class ProxyTransport : std::uint8_t { Stream = 1, Datagram = 2 };
enum class ProxyError { NeedMore, Invalid, Unsupported };

struct ProxyHeader {
    std::optional<Endpoint> source;
    std::optional<Endpoint> destination;
    std::size_t size;
};

[[nodiscard]] std::expected<ProxyHeader, ProxyError>
parse_proxy_header(std::span<const std::uint8_t> bytes, ProxyTransport transport) noexcept;

} // namespace erikslund::mmproxy
