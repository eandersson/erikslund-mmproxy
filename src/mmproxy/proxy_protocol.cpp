#include "mmproxy/proxy_protocol.hpp"

#include <algorithm>
#include <array>
#include <string_view>

namespace erikslund::mmproxy {

namespace {

constexpr std::string_view kV1Signature = "PROXY ";
constexpr std::string_view kV1Unknown = "UNKNOWN";
constexpr std::size_t kLineEndingBytes = 2;
constexpr std::array<std::uint8_t, 12> kV2Signature{
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 'Q', 'U', 'I', 'T', 0x0a};
constexpr std::size_t kV2VersionAndCommandOffset = kV2Signature.size();
constexpr std::size_t kV2FamilyAndTransportOffset = kV2VersionAndCommandOffset + 1;
constexpr std::size_t kV2LengthOffset = kV2FamilyAndTransportOffset + 1;
constexpr unsigned int kNibbleBits = 4;
constexpr std::uint8_t kLowNibbleMask = 0x0f;
constexpr std::uint8_t kV2Version = 2;
constexpr std::uint8_t kV2LocalCommand = 0;
constexpr std::uint8_t kV2ProxyCommand = 1;
constexpr std::uint8_t kV2Ipv4Family = 1;
constexpr std::uint8_t kV2Ipv6Family = 2;
constexpr std::size_t kWirePortBytes = 2;
constexpr std::size_t kV1AddressFieldCount = 4;

std::uint16_t read_wire_u16(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept {
    constexpr unsigned int kLowByteBits = 8;
    return static_cast<std::uint16_t>((bytes[offset] << kLowByteBits) | bytes[offset + 1]);
}

bool has_leading_zero(std::string_view number) noexcept {
    return number.size() > 1 && number.front() == '0';
}

std::expected<ProxyHeader, ProxyError> parse_v1_addresses(std::string_view text, int family,
                                                         std::size_t size) noexcept {
    std::array<std::string_view, kV1AddressFieldCount> fields;
    for (auto& field : std::span{fields}.first<kV1AddressFieldCount - 1>()) {
        const std::size_t separator = text.find(' ');
        if (separator == std::string_view::npos)
            return std::unexpected(ProxyError::Invalid);
        field = text.substr(0, separator);
        text.remove_prefix(separator + 1);
    }
    fields.back() = text;

    const auto [source_text, destination_text, source_port_text, destination_port_text] = fields;
    if (has_leading_zero(source_port_text) || has_leading_zero(destination_port_text))
        return std::unexpected(ProxyError::Invalid);

    const auto source_ip = parse_ip_address(source_text, family);
    const auto destination_ip = parse_ip_address(destination_text, family);
    const auto source_port = parse_port(source_port_text);
    const auto destination_port = parse_port(destination_port_text);
    if (!source_ip || !destination_ip || !source_port || !destination_port)
        return std::unexpected(ProxyError::Invalid);

    const Endpoint source{.address = unmap_ipv4(*source_ip), .port = *source_port};
    if (!usable_transparent_source(source))
        return std::unexpected(ProxyError::Invalid);

    const Endpoint destination{.address = unmap_ipv4(*destination_ip), .port = *destination_port};
    return ProxyHeader{.source = source, .destination = destination, .size = size};
}

std::expected<ProxyHeader, ProxyError> parse_v1(std::span<const std::uint8_t> bytes) noexcept {
    const std::string_view prefix{reinterpret_cast<const char*>(bytes.data()),
                                  std::min(bytes.size(), kMaxProxyV1HeaderSize)};
    if (!prefix.starts_with(kV1Signature.substr(0, prefix.size())))
        return std::unexpected(ProxyError::Invalid);

    const std::size_t end = prefix.find_first_of("\r\n");
    if (end == std::string_view::npos || (prefix[end] == '\r' && end + 1 == prefix.size())) {
        const auto error = prefix.size() < kMaxProxyV1HeaderSize ? ProxyError::NeedMore
                                                               : ProxyError::Invalid;
        return std::unexpected(error);
    }

    if (prefix[end] != '\r' || prefix[end + 1] != '\n' || end < kV1Signature.size())
        return std::unexpected(ProxyError::Invalid);

    const auto line = prefix.substr(kV1Signature.size(), end - kV1Signature.size());
    const std::size_t size = end + kLineEndingBytes;
    const std::size_t separator = line.find(' ');
    const auto protocol = line.substr(0, separator);
    if (protocol == kV1Unknown)
        return ProxyHeader{.source = std::nullopt, .destination = std::nullopt, .size = size};

    if (separator == std::string_view::npos)
        return std::unexpected(ProxyError::Invalid);

    if (protocol == "TCP4")
        return parse_v1_addresses(line.substr(separator + 1), AF_INET, size);
    if (protocol == "TCP6")
        return parse_v1_addresses(line.substr(separator + 1), AF_INET6, size);
    return std::unexpected(ProxyError::Invalid);
}

std::expected<ProxyHeader, ProxyError>
parse_v2_addresses(std::span<const std::uint8_t> address_bytes, int family,
                   std::size_t size) noexcept {
    const std::size_t address_size = ip_address_size(family);
    const auto source_address_bytes = address_bytes.first(address_size);
    const auto destination_address_bytes = address_bytes.subspan(address_size, address_size);
    const std::size_t ports_offset = source_address_bytes.size() + destination_address_bytes.size();

    IpAddress source_ip{.family = family};
    IpAddress destination_ip{.family = family};
    std::ranges::copy(source_address_bytes, source_ip.bytes.begin());
    std::ranges::copy(destination_address_bytes, destination_ip.bytes.begin());

    const Endpoint source{.address = unmap_ipv4(source_ip),
                          .port = read_wire_u16(address_bytes, ports_offset)};
    if (!usable_transparent_source(source))
        return std::unexpected(ProxyError::Invalid);

    const Endpoint destination{.address = unmap_ipv4(destination_ip),
                               .port = read_wire_u16(address_bytes, ports_offset + kWirePortBytes)};
    return ProxyHeader{.source = source, .destination = destination, .size = size};
}

std::expected<ProxyHeader, ProxyError> parse_v2(std::span<const std::uint8_t> bytes,
                                               ProxyTransport transport) noexcept {
    const auto signature_size = std::min(bytes.size(), kV2Signature.size());
    if (!std::ranges::equal(bytes.first(signature_size),
                            std::span{kV2Signature}.first(signature_size)))
        return std::unexpected(ProxyError::Invalid);
    if (bytes.size() < kProxyV2FixedHeaderSize)
        return std::unexpected(ProxyError::NeedMore);

    const auto version_and_command = bytes[kV2VersionAndCommandOffset];
    const auto command = version_and_command & kLowNibbleMask;
    if ((version_and_command >> kNibbleBits) != kV2Version || command > kV2ProxyCommand)
        return std::unexpected(ProxyError::Invalid);

    const std::size_t body_size = read_wire_u16(bytes, kV2LengthOffset);
    const std::size_t size = kProxyV2FixedHeaderSize + body_size;
    if (command == kV2LocalCommand) {
        if (bytes.size() < size)
            return std::unexpected(ProxyError::NeedMore);
        return ProxyHeader{.source = std::nullopt, .destination = std::nullopt, .size = size};
    }

    const auto family_and_transport = bytes[kV2FamilyAndTransportOffset];
    const auto wire_family = family_and_transport >> kNibbleBits;
    if ((family_and_transport & kLowNibbleMask) != static_cast<std::uint8_t>(transport) ||
        (wire_family != kV2Ipv4Family && wire_family != kV2Ipv6Family))
        return std::unexpected(ProxyError::Unsupported);

    const int family = wire_family == kV2Ipv4Family ? AF_INET : AF_INET6;
    const std::size_t address_and_ports_size = 2 * (ip_address_size(family) + kWirePortBytes);
    if (body_size < address_and_ports_size)
        return std::unexpected(ProxyError::Invalid);
    if (bytes.size() < size)
        return std::unexpected(ProxyError::NeedMore);

    const auto address_bytes = bytes.subspan(kProxyV2FixedHeaderSize, address_and_ports_size);
    return parse_v2_addresses(address_bytes, family, size);
}

} // namespace

std::expected<ProxyHeader, ProxyError> parse_proxy_header(std::span<const std::uint8_t> bytes,
                                                         ProxyTransport transport) noexcept {
    if (bytes.empty())
        return std::unexpected(ProxyError::NeedMore);
    if (bytes.front() == kV2Signature.front())
        return parse_v2(bytes, transport);
    if (bytes.front() != kV1Signature.front())
        return std::unexpected(ProxyError::Invalid);
    if (transport != ProxyTransport::Stream)
        return std::unexpected(ProxyError::Unsupported);
    return parse_v1(bytes);
}

} // namespace erikslund::mmproxy
