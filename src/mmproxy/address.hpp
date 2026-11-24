#pragma once
// Numeric IP addresses, socket endpoints, and trusted relay networks.

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>
#include <vector>

#include <sys/socket.h>

namespace erikslund::mmproxy {

inline constexpr std::size_t kIpv4AddressBytes = 4;
inline constexpr std::size_t kIpv6AddressBytes = 16;

[[nodiscard]] std::size_t ip_address_size(int family) noexcept;

struct IpAddress {
    int family{AF_UNSPEC};
    std::array<std::uint8_t, kIpv6AddressBytes> bytes{};

    [[nodiscard]] bool is_loopback() const noexcept;
    [[nodiscard]] bool is_wildcard() const noexcept;
    auto operator<=>(const IpAddress&) const = default;
};

struct Endpoint {
    IpAddress address;
    std::uint16_t port{};
    std::uint32_t scope_id{};

    auto operator<=>(const Endpoint&) const = default;
};

struct SocketAddress {
    sockaddr_storage storage{};
    socklen_t length{};

    [[nodiscard]] const sockaddr* data() const noexcept;
};

enum class AddressError { InvalidAddress, InvalidPort };

[[nodiscard]] std::expected<IpAddress, AddressError>
parse_ip_address(std::string_view text, int family = AF_UNSPEC) noexcept;
[[nodiscard]] std::expected<std::uint16_t, AddressError> parse_port(std::string_view text) noexcept;
[[nodiscard]] std::expected<Endpoint, AddressError> parse_endpoint(std::string_view text) noexcept;
[[nodiscard]] IpAddress unmap_ipv4(const IpAddress& address) noexcept;
[[nodiscard]] SocketAddress to_socket_address(const Endpoint& endpoint) noexcept;
[[nodiscard]] std::optional<Endpoint> from_socket_address(const sockaddr_storage& address) noexcept;
[[nodiscard]] bool usable_transparent_source(const Endpoint& endpoint) noexcept;
[[nodiscard]] IpAddress client_network(const IpAddress& address) noexcept;
[[nodiscard]] bool relay_may_claim(const Endpoint& relay, const Endpoint& claimed) noexcept;
[[nodiscard]] bool relay_may_claim(const Endpoint& relay,
                                   const std::optional<Endpoint>& claimed) noexcept;

class TrustList {
public:
    enum class Everyone { Count, Ignore };

    [[nodiscard]] bool add(std::string_view text);
    [[nodiscard]] bool contains(const IpAddress& address) const noexcept;
    [[nodiscard]] bool overlaps(const IpAddress& network, unsigned int prefix_bits,
                                Everyone everyone = Everyone::Count) const noexcept;
    [[nodiscard]] bool trusts_everyone() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

private:
    struct Network {
        IpAddress address;
        unsigned int prefix_bits;
    };

    std::vector<Network> networks_;
};

} // namespace erikslund::mmproxy
