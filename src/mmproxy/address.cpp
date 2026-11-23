#include "mmproxy/address.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <span>
#include <system_error>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace erikslund::mmproxy {

namespace {

constexpr unsigned int kBitsPerByte = 8;
constexpr unsigned int kAllBits = 0xff;
constexpr std::uint8_t kIpv4LoopbackFirstByte = 127;
constexpr std::uint8_t kIpv4MulticastMask = 0xf0;
constexpr std::uint8_t kIpv4MulticastPrefix = 0xe0;
constexpr std::uint8_t kIpv6MulticastPrefix = 0xff;
constexpr std::uint8_t kIpv6LinkLocalFirstByte = 0xfe;
constexpr std::uint8_t kIpv6LinkLocalMask = 0xc0;
constexpr std::uint8_t kIpv6LinkLocalSecondByte = 0x80;
constexpr std::array<std::uint8_t, kIpv4AddressBytes> kIpv4BroadcastBytes{255, 255, 255, 255};
constexpr std::array<std::uint8_t, kIpv6AddressBytes> kIpv6LoopbackBytes{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
constexpr std::size_t kMappedPrefixBytes = kIpv6AddressBytes - kIpv4AddressBytes;
constexpr std::size_t kIpv6SourcePrefixBytes = 8;
constexpr std::array<std::uint8_t, kMappedPrefixBytes> kNat64Prefix{
    0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0};
constexpr std::array<std::uint8_t, kMappedPrefixBytes> kMappedPrefix{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

bool is_ipv4_mapped(const IpAddress& address) noexcept {
    return address.family == AF_INET6 &&
           std::ranges::equal(std::span{address.bytes}.first<kMappedPrefixBytes>(), kMappedPrefix);
}

IpAddress embedded_ipv4(const IpAddress& address) noexcept {
    IpAddress ipv4{.family = AF_INET};
    std::ranges::copy(std::span{address.bytes}.last<kIpv4AddressBytes>(), ipv4.bytes.begin());
    return ipv4;
}

bool has_host_bits(const IpAddress& address, unsigned int prefix_bits) noexcept {
    const std::size_t size = address.family == AF_INET ? kIpv4AddressBytes : kIpv6AddressBytes;
    for (std::size_t index = 0; index < size; ++index) {
        const auto first_bit = static_cast<unsigned int>(index * kBitsPerByte);
        const unsigned int network_bits =
            prefix_bits > first_bit ? std::min(prefix_bits - first_bit, kBitsPerByte) : 0;
        const auto host_mask = static_cast<std::uint8_t>(kAllBits >> network_bits);
        if ((address.bytes[index] & host_mask) != 0)
            return true;
    }
    return false;
}

bool matches_prefix(const IpAddress& address, const IpAddress& network,
                    unsigned int prefix_bits) noexcept {
    const std::size_t full_bytes = prefix_bits / kBitsPerByte;
    if (!std::ranges::equal(std::span{address.bytes}.first(full_bytes),
                            std::span{network.bytes}.first(full_bytes)))
        return false;

    const unsigned int partial_bits = prefix_bits % kBitsPerByte;
    if (partial_bits == 0)
        return true;

    const unsigned int shift = kBitsPerByte - partial_bits;
    return (address.bytes[full_bytes] >> shift) == (network.bytes[full_bytes] >> shift);
}

} // namespace

bool IpAddress::is_loopback() const noexcept {
    return (family == AF_INET && bytes.front() == kIpv4LoopbackFirstByte) ||
           (family == AF_INET6 && bytes == kIpv6LoopbackBytes);
}

const sockaddr* SocketAddress::data() const noexcept {
    return reinterpret_cast<const sockaddr*>(&storage);
}

IpAddress unmap_ipv4(const IpAddress& address) noexcept {
    return is_ipv4_mapped(address) ? embedded_ipv4(address) : address;
}

IpAddress client_source(const IpAddress& address) noexcept {
    IpAddress source = unmap_ipv4(address);
    if (source.family != AF_INET6)
        return source;
    if (std::ranges::equal(std::span{source.bytes}.first<kMappedPrefixBytes>(), kNat64Prefix))
        return embedded_ipv4(source);
    std::ranges::fill(std::span{source.bytes}.subspan(kIpv6SourcePrefixBytes), 0);
    return source;
}

std::expected<IpAddress, AddressError> parse_ip_address(std::string_view text, int family) noexcept {
    std::array<char, INET6_ADDRSTRLEN> host{};
    if (text.empty() || text.size() >= host.size() || text.find('\0') != std::string_view::npos)
        return std::unexpected(AddressError::InvalidAddress);
    std::ranges::copy(text, host.begin());

    IpAddress address;
    if ((family == AF_UNSPEC || family == AF_INET) &&
        inet_pton(AF_INET, host.data(), address.bytes.data()) == 1) {
        address.family = AF_INET;
        return address;
    }

    if ((family == AF_UNSPEC || family == AF_INET6) &&
        inet_pton(AF_INET6, host.data(), address.bytes.data()) == 1) {
        address.family = AF_INET6;
        return address;
    }

    return std::unexpected(AddressError::InvalidAddress);
}

std::expected<std::uint16_t, AddressError> parse_port(std::string_view text) noexcept {
    if (text.empty())
        return std::unexpected(AddressError::InvalidPort);

    std::uint16_t port{};
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto [next, error] = std::from_chars(begin, end, port);
    if (error != std::errc{} || next != end)
        return std::unexpected(AddressError::InvalidPort);
    return port;
}

std::expected<Endpoint, AddressError> parse_endpoint(std::string_view text) noexcept {
    const std::size_t separator = text.rfind(':');
    if (separator == std::string_view::npos)
        return std::unexpected(AddressError::InvalidAddress);

    auto host = text.substr(0, separator);
    int family = AF_INET;
    if (host.starts_with('[') && host.ends_with(']')) {
        host = host.substr(1, host.size() - 2);
        family = AF_INET6;
    }

    const auto address = parse_ip_address(host, family);
    const auto port = parse_port(text.substr(separator + 1));
    if (!address)
        return std::unexpected(address.error());
    if (!port)
        return std::unexpected(port.error());

    return Endpoint{.address = *address, .port = *port};
}

SocketAddress to_socket_address(const Endpoint& endpoint) noexcept {
    SocketAddress result;
    if (endpoint.address.family == AF_INET) {
        sockaddr_in ipv4{};
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(endpoint.port);
        std::memcpy(&ipv4.sin_addr, endpoint.address.bytes.data(), kIpv4AddressBytes);
        std::memcpy(&result.storage, &ipv4, sizeof(ipv4));
        result.length = static_cast<socklen_t>(sizeof(ipv4));
    } else if (endpoint.address.family == AF_INET6) {
        sockaddr_in6 ipv6{};
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(endpoint.port);
        ipv6.sin6_scope_id = endpoint.scope_id;
        std::memcpy(&ipv6.sin6_addr, endpoint.address.bytes.data(), kIpv6AddressBytes);
        std::memcpy(&result.storage, &ipv6, sizeof(ipv6));
        result.length = static_cast<socklen_t>(sizeof(ipv6));
    }
    return result;
}

std::optional<Endpoint> from_socket_address(const sockaddr_storage& address) noexcept {
    if (address.ss_family == AF_INET) {
        sockaddr_in ipv4{};
        std::memcpy(&ipv4, &address, sizeof(ipv4));
        IpAddress ip{.family = AF_INET};
        std::memcpy(ip.bytes.data(), &ipv4.sin_addr, kIpv4AddressBytes);
        return Endpoint{.address = ip, .port = ntohs(ipv4.sin_port)};
    }

    if (address.ss_family == AF_INET6) {
        sockaddr_in6 ipv6{};
        std::memcpy(&ipv6, &address, sizeof(ipv6));
        IpAddress ip{.family = AF_INET6};
        std::memcpy(ip.bytes.data(), &ipv6.sin6_addr, kIpv6AddressBytes);

        if (is_ipv4_mapped(ip))
            return Endpoint{.address = embedded_ipv4(ip), .port = ntohs(ipv6.sin6_port)};
        return Endpoint{.address = ip, .port = ntohs(ipv6.sin6_port),
                        .scope_id = ipv6.sin6_scope_id};
    }

    return std::nullopt;
}

bool usable_transparent_source(const Endpoint& endpoint) noexcept {
    if (endpoint.port == 0)
        return false;

    const auto& bytes = endpoint.address.bytes;
    if (endpoint.address.family == AF_INET) {
        const auto ipv4 = std::span{bytes}.first<kIpv4AddressBytes>();
        const bool wildcard = std::ranges::all_of(ipv4, [](auto byte) { return byte == 0; });
        const bool multicast = (bytes.front() & kIpv4MulticastMask) == kIpv4MulticastPrefix;
        return !wildcard && !multicast && !std::ranges::equal(ipv4, kIpv4BroadcastBytes);
    }

    if (endpoint.address.family == AF_INET6) {
        const bool wildcard = std::ranges::all_of(bytes, [](auto byte) { return byte == 0; });
        const bool multicast = bytes.front() == kIpv6MulticastPrefix;
        const bool link_local = bytes.front() == kIpv6LinkLocalFirstByte &&
                                (bytes[1] & kIpv6LinkLocalMask) == kIpv6LinkLocalSecondByte;
        return !wildcard && !multicast && !link_local && !is_ipv4_mapped(endpoint.address);
    }

    return false;
}

bool claim_fits_relay(const Endpoint& claimed, const Endpoint& relay) noexcept {
    return !claimed.address.is_loopback() || relay.address.is_loopback();
}

bool TrustList::add(std::string_view text) {
    const auto separator = text.find('/');
    auto address = parse_ip_address(text.substr(0, separator));
    if (!address)
        return false;

    const auto max_prefix_bits = static_cast<unsigned int>(
        (address->family == AF_INET ? kIpv4AddressBytes : kIpv6AddressBytes) * kBitsPerByte);
    unsigned int prefix_bits = max_prefix_bits;
    if (separator != std::string_view::npos) {
        const auto length_text = text.substr(separator + 1);
        const char* const begin = length_text.data();
        const char* const end = begin + length_text.size();
        const auto [next, error] = std::from_chars(begin, end, prefix_bits);
        if (error != std::errc{} || next != end || prefix_bits > max_prefix_bits)
            return false;
    }

    if (is_ipv4_mapped(*address)) {
        constexpr unsigned int kMappedPrefixBits = kMappedPrefixBytes * kBitsPerByte;
        if (prefix_bits < kMappedPrefixBits)
            return false;
        *address = embedded_ipv4(*address);
        prefix_bits -= kMappedPrefixBits;
    }

    if (has_host_bits(*address, prefix_bits))
        return false;
    networks_.push_back({.address = *address, .prefix_bits = prefix_bits});
    return true;
}

bool TrustList::contains(const IpAddress& address) const noexcept {
    const IpAddress normalized = unmap_ipv4(address);
    return std::ranges::any_of(networks_, [&normalized](const Network& network) {
        return normalized.family == network.address.family &&
               matches_prefix(normalized, network.address, network.prefix_bits);
    });
}

bool TrustList::overlaps(const IpAddress& network, unsigned int prefix_bits,
                         bool count_everyone) const noexcept {
    return std::ranges::any_of(networks_, [&](const Network& entry) {
        const bool counted = count_everyone || entry.prefix_bits != 0;
        return counted && entry.address.family == network.family &&
               matches_prefix(entry.address, network, std::min(entry.prefix_bits, prefix_bits));
    });
}

bool TrustList::trusts_everyone() const noexcept {
    return std::ranges::any_of(networks_,
                               [](const Network& entry) { return entry.prefix_bits == 0; });
}

bool TrustList::empty() const noexcept {
    return networks_.empty();
}

} // namespace erikslund::mmproxy
