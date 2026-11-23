#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "mmproxy/address.hpp"
#include "mmproxy/proxy_protocol.hpp"

namespace erikslund::mmproxy {
namespace {

constexpr std::uint32_t kFuzzSeed = 20'261'123;
constexpr int kFuzzIterations = 20'000;
constexpr std::size_t kMaxFuzzBytes = 160;
constexpr int kMaxMutations = 3;
constexpr std::size_t kVersionCommandOffset = 12;
constexpr std::size_t kFamilyTransportOffset = 13;
constexpr std::size_t kLengthLowByteOffset = 15;
constexpr std::size_t kV1LongestHeaderBytes = 107;

// A v2 STREAM header for 192.0.2.20:12345 -> 198.51.100.5:443 with one TLV, then a payload byte.
constexpr std::array<std::uint8_t, 34> kStreamHeaderWithPayload{
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    0x21, 0x11, 0x00, 0x11,
    192, 0, 2, 20, 198, 51, 100, 5, 0x30, 0x39, 0x01, 0xbb,
    0xee, 0x00, 0x02, 0x55, 0x66,
    0x42,
};
constexpr std::size_t kStreamHeaderBytes = kStreamHeaderWithPayload.size() - 1;
constexpr std::string_view kV1Header = "PROXY TCP4 192.0.2.20 198.51.100.5 12345 443\r\n";

std::span<const std::uint8_t> bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

std::vector<std::uint8_t> with_byte(std::span<const std::uint8_t> original, std::size_t offset,
                                    std::uint8_t value) {
    std::vector<std::uint8_t> copy(original.begin(), original.end());
    copy[offset] = value;
    return copy;
}

ProxyError error_of(std::span<const std::uint8_t> input, ProxyTransport transport) {
    const auto result = parse_proxy_header(input, transport);
    REQUIRE_FALSE(result.has_value());
    return result.error();
}

// An accepted header must end inside the input and name a source that can be bound.
void check_invariants(std::span<const std::uint8_t> input, ProxyTransport transport) {
    const auto result = parse_proxy_header(input, transport);
    if (!result)
        return;
    CHECK(result->size <= input.size());
    if (result->source)
        CHECK(usable_transparent_source(*result->source));
}

TEST_CASE("PROXY v2 waits for every byte of its declared length") {
    const auto header = std::span(kStreamHeaderWithPayload).first(kStreamHeaderBytes);
    for (std::size_t length = 1; length < header.size(); ++length)
        CHECK(error_of(header.first(length), ProxyTransport::Stream) == ProxyError::NeedMore);
    const auto complete = parse_proxy_header(header, ProxyTransport::Stream);
    REQUIRE(complete.has_value());
    CHECK(complete->size == header.size());
}

TEST_CASE("PROXY v2 rejects bad versions, commands, families and lengths") {
    const auto header = std::span(kStreamHeaderWithPayload);
    constexpr std::uint8_t kVersionOne = 0x11;
    constexpr std::uint8_t kUnknownCommand = 0x22;
    constexpr std::uint8_t kUnspecifiedStream = 0x01;
    constexpr std::uint8_t kUnixStream = 0x31;
    constexpr std::uint8_t kBodyShorterThanAddresses = 11;
    constexpr std::uint8_t kBrokenSignatureByte = 0x0b;

    CHECK(error_of(with_byte(header, kVersionCommandOffset, kVersionOne), ProxyTransport::Stream) ==
          ProxyError::Invalid);
    CHECK(error_of(with_byte(header, kVersionCommandOffset, kUnknownCommand),
                   ProxyTransport::Stream) == ProxyError::Invalid);
    CHECK(error_of(with_byte(header, kFamilyTransportOffset, kUnspecifiedStream),
                   ProxyTransport::Stream) == ProxyError::Unsupported);
    CHECK(error_of(with_byte(header, kFamilyTransportOffset, kUnixStream),
                   ProxyTransport::Stream) == ProxyError::Unsupported);
    CHECK(error_of(header, ProxyTransport::Datagram) == ProxyError::Unsupported);
    CHECK(error_of(with_byte(header, kLengthLowByteOffset, kBodyShorterThanAddresses),
                   ProxyTransport::Stream) == ProxyError::Invalid);
    CHECK(error_of(with_byte(header, 1, kBrokenSignatureByte), ProxyTransport::Stream) ==
          ProxyError::Invalid);
}

TEST_CASE("PROXY v1 enforces the 107-byte line limit") {
    const std::string prefix = "PROXY UNKNOWN ";
    const std::string longest =
        prefix + std::string(kV1LongestHeaderBytes - prefix.size() - 2, 'x') + "\r\n";
    REQUIRE(longest.size() == kV1LongestHeaderBytes);
    CHECK(parse_proxy_header(bytes(longest), ProxyTransport::Stream).has_value());

    const std::string oversized =
        prefix + std::string(longest.size() - prefix.size() - 1, 'x') + "\r\n";
    CHECK(error_of(bytes(oversized), ProxyTransport::Stream) == ProxyError::Invalid);
}

TEST_CASE("PROXY v1 rejects malformed fields and the datagram transport") {
    const std::string embedded_nul = std::string("PROXY TCP4 192.0.2.20") + '\0' +
                                     " 198.51.100.5 12345 443\r\n";
    const std::array<std::string_view, 9> rejected{
        "PROXY TCP4 192.0.2.20 198.51.100.5 +1 443\r\n",
        "PROXY TCP4 192.0.2.20 198.51.100.5 -1 443\r\n",
        "PROXY TCP4 192.0.2.20 198.51.100.5 0123 443\r\n",
        "proxy tcp4 192.0.2.20 198.51.100.5 12345 443\r\n",
        "PROXY TCP4 192.0.2.20 198.51.100.5 12345\r\n",
        "PROXY TCP4 192.0.2.20 198.51.100.5 12345 443 7\r\n",
        "PROXY TCP4 2001:db8::1 198.51.100.5 12345 443\r\n",
        "PROXY TCP6 192.0.2.20 2001:db8::5 12345 443\r\n",
        embedded_nul,
    };
    for (const auto line : rejected)
        CHECK_FALSE(parse_proxy_header(bytes(line), ProxyTransport::Stream).has_value());
    CHECK(error_of(bytes(kV1Header), ProxyTransport::Datagram) == ProxyError::Unsupported);
}

TEST_CASE("Random bytes never yield a header outside the input") {
    std::mt19937 generator(kFuzzSeed);
    std::uniform_int_distribution<std::size_t> length_distribution(0, kMaxFuzzBytes);
    std::uniform_int_distribution<int> byte_distribution(0, 255);
    std::uniform_int_distribution<int> prefix_distribution(0, 2);
    const auto v2_prefix = std::span(kStreamHeaderWithPayload).first(kVersionCommandOffset + 1);
    const auto v1_prefix = bytes("PROXY TCP4 ");

    for (int iteration = 0; iteration < kFuzzIterations; ++iteration) {
        std::vector<std::uint8_t> input(length_distribution(generator));
        for (auto& byte : input)
            byte = static_cast<std::uint8_t>(byte_distribution(generator));
        // Most inputs start with a real signature, so the fuzz reaches the field parsers.
        const int prefix_choice = prefix_distribution(generator);
        const auto prefix = prefix_choice == 0 ? v2_prefix : v1_prefix;
        if (prefix_choice < 2)
            std::copy_n(prefix.begin(), std::min(prefix.size(), input.size()), input.begin());
        check_invariants(input, ProxyTransport::Stream);
        check_invariants(input, ProxyTransport::Datagram);
    }
}

TEST_CASE("Mutated valid headers never yield a header outside the input") {
    std::mt19937 generator(kFuzzSeed);
    std::uniform_int_distribution<int> byte_distribution(0, 255);
    std::uniform_int_distribution<int> mutation_distribution(1, kMaxMutations);
    const std::array<std::span<const std::uint8_t>, 2> originals{
        std::span(kStreamHeaderWithPayload), bytes(kV1Header)};

    for (int iteration = 0; iteration < kFuzzIterations; ++iteration) {
        const auto original = originals[static_cast<std::size_t>(iteration) % originals.size()];
        std::vector<std::uint8_t> input(original.begin(), original.end());
        std::uniform_int_distribution<std::size_t> offset_distribution(0, input.size() - 1);
        for (int mutation = mutation_distribution(generator); mutation > 0; --mutation) {
            const auto value = static_cast<std::uint8_t>(byte_distribution(generator));
            input[offset_distribution(generator)] = value;
        }
        check_invariants(input, ProxyTransport::Stream);
        check_invariants(input, ProxyTransport::Datagram);
    }
}

} // namespace
} // namespace erikslund::mmproxy
