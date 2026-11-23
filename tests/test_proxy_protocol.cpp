#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "mmproxy/address.hpp"
#include "mmproxy/proxy_protocol.hpp"

namespace erikslund::mmproxy {
namespace {

std::span<const std::uint8_t> bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

constexpr std::array<std::uint8_t, 34> kDatagramWithTlvAndPayload{
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    0x21, 0x12, 0x00, 0x11,
    192, 0, 2, 20, 198, 51, 100, 5, 0x30, 0x39, 0x01, 0xbb,
    0xee, 0x00, 0x02, 0x55, 0x66,
    0x42,
};

// A v2 STREAM header whose IPv6 addresses are ::ffff:192.0.2.20 and ::ffff:198.51.100.5.
constexpr std::array<std::uint8_t, 52> kMappedStreamHeader{
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    0x21, 0x21, 0x00, 0x24,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 20,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 5,
    0x30, 0x39, 0x01, 0xbb,
};

TEST_CASE("PROXY v1 consumes exactly the complete header") {
    constexpr std::string_view header = "PROXY TCP4 192.0.2.20 198.51.100.5 12345 443\r\n";
    for (std::size_t length = 0; length < header.size(); ++length) {
        const auto result = parse_proxy_header(bytes(header).first(length), ProxyTransport::Stream);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == ProxyError::NeedMore);
    }

    const std::string message = std::string(header) + "application payload";
    const auto result = parse_proxy_header(bytes(message), ProxyTransport::Stream);
    REQUIRE(result.has_value());
    REQUIRE(result->source.has_value());
    REQUIRE(result->destination.has_value());
    CHECK(*result->source == parse_endpoint("192.0.2.20:12345").value());
    CHECK(*result->destination == parse_endpoint("198.51.100.5:443").value());
    CHECK(result->size == header.size());
}

TEST_CASE("PROXY v1 rejects ambiguous framing and unusable sources") {
    constexpr std::array<std::string_view, 7> rejected{
        "PROXY TCP4 192.0.2.20 198.51.100.5 12345 443\n",
        "PROXY TCP4 192.0.2.20 198.51.100.5 12345 443 \r\n",
        "PROXY TCP4  192.0.2.20 198.51.100.5 12345 443\r\n",
        "PROXY TCP4 192.0.2.20 invalid-destination 12345 443\r\n",
        "PROXY TCP4 192.0.2.20 198.51.100.5 65536 443\r\n",
        "PROXY TCP4 192.0.2.20 198.51.100.5 0 443\r\n",
        "PROXY TCP4 224.0.0.1 198.51.100.5 12345 443\r\n",
    };
    for (const auto line : rejected)
        CHECK_FALSE(parse_proxy_header(bytes(line), ProxyTransport::Stream).has_value());
}

TEST_CASE("PROXY headers forward IPv4-mapped clients as IPv4") {
    const auto expected_source = parse_endpoint("192.0.2.20:12345").value();
    const auto expected_destination = parse_endpoint("198.51.100.5:443").value();

    const auto v1 = parse_proxy_header(
        bytes("PROXY TCP6 ::ffff:192.0.2.20 ::ffff:198.51.100.5 12345 443\r\n"),
        ProxyTransport::Stream);
    REQUIRE(v1.has_value());
    CHECK(*v1->source == expected_source);
    CHECK(*v1->destination == expected_destination);

    const auto v2 = parse_proxy_header(kMappedStreamHeader, ProxyTransport::Stream);
    REQUIRE(v2.has_value());
    CHECK(*v2->source == expected_source);
    CHECK(*v2->destination == expected_destination);
    CHECK(v2->size == kMappedStreamHeader.size());
}

TEST_CASE("PROXY v2 uses its declared length and validates the transport") {
    const auto datagram = std::span(kDatagramWithTlvAndPayload);
    const auto result = parse_proxy_header(datagram, ProxyTransport::Datagram);
    REQUIRE(result.has_value());
    REQUIRE(result->source.has_value());
    CHECK(*result->source == parse_endpoint("192.0.2.20:12345").value());
    CHECK(result->size == datagram.size() - 1);
    CHECK_FALSE(parse_proxy_header(datagram, ProxyTransport::Stream).has_value());
    CHECK_FALSE(parse_proxy_header(datagram.first(result->size - 1), ProxyTransport::Datagram)
                    .has_value());
}

TEST_CASE("PROXY v1 UNKNOWN and v2 LOCAL carry no forwardable identity") {
    const auto unknown = parse_proxy_header(bytes("PROXY UNKNOWN\r\n"), ProxyTransport::Stream);
    REQUIRE(unknown.has_value());
    CHECK_FALSE(unknown->source.has_value());

    auto local = kDatagramWithTlvAndPayload;
    local[12] = 0x20;
    const auto local_result = parse_proxy_header(local, ProxyTransport::Stream);
    REQUIRE(local_result.has_value());
    CHECK_FALSE(local_result->source.has_value());
    CHECK(local_result->size == local.size() - 1);
}

} // namespace
} // namespace erikslund::mmproxy
