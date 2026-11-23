#include <doctest/doctest.h>

#include <array>
#include <string_view>

#include <netinet/in.h>

#include "mmproxy/address.hpp"

namespace erikslund::mmproxy {
namespace {

TEST_CASE("Trust lists match binary addresses at correct CIDR boundaries") {
    TrustList trusted;
    CHECK(trusted.empty());
    REQUIRE(trusted.add("192.0.2.192/26"));
    REQUIRE(trusted.add("2001:db8:abc0::/42"));
    REQUIRE(trusted.add("::ffff:198.51.100.10/128"));
    CHECK_FALSE(trusted.add("127.0.0.0/33"));
    CHECK_FALSE(trusted.add("::/129"));
    CHECK_FALSE(trusted.add("127.0.0.1/99999999999999999999999"));
    CHECK_FALSE(trusted.add("::ffff:198.51.100.0/95"));
    CHECK_FALSE(trusted.add("192.0.2.1/"));
    CHECK_FALSE(trusted.add("192.0.2.1/+8"));

    const auto contains = [&trusted](std::string_view endpoint) {
        return trusted.contains(parse_endpoint(endpoint).value().address);
    };
    CHECK(contains("192.0.2.192:443"));
    CHECK(contains("192.0.2.255:443"));
    CHECK_FALSE(contains("192.0.2.191:443"));
    CHECK(contains("[2001:db8:abff::1]:443"));
    CHECK_FALSE(contains("[2001:db8:ac00::1]:443"));
    CHECK(contains("198.51.100.10:443"));
    CHECK(contains("[::ffff:198.51.100.10]:443"));
    CHECK_FALSE(contains("198.51.100.11:443"));
}

TEST_CASE("Trust list entries must not set host bits, which would widen them silently") {
    TrustList trusted;
    CHECK_FALSE(trusted.add("10.42.0.5/3"));
    CHECK_FALSE(trusted.add("192.0.2.193/26"));
    CHECK_FALSE(trusted.add("2001:db8::1/64"));
    CHECK(trusted.add("10.42.0.5/32"));
    CHECK(trusted.add("10.42.0.0/24"));
    CHECK(trusted.add("2001:db8::/64"));
    CHECK(trusted.add("::ffff:192.0.2.0/120"));
}

TEST_CASE("Trust lists report overlaps and /0 entries") {
    TrustList trusted;
    REQUIRE(trusted.add("10.0.0.0/8"));
    const auto ip = [](std::string_view text) { return parse_ip_address(text).value(); };
    CHECK(trusted.overlaps(ip("10.42.0.10"), 32));
    CHECK(trusted.overlaps(ip("0.0.0.0"), 0));
    CHECK_FALSE(trusted.overlaps(ip("127.0.0.0"), 8));
    CHECK_FALSE(trusted.trusts_everyone());
    REQUIRE(trusted.add("::/0"));
    CHECK(trusted.trusts_everyone());
    CHECK(trusted.overlaps(ip("::1"), 128));
}

TEST_CASE("Only a relay on this host may claim a loopback client") {
    const auto remote_relay = parse_endpoint("192.0.2.25:40000").value();
    const auto local_relay = parse_endpoint("127.0.0.1:40000").value();
    const auto loopback_claim = parse_endpoint("127.0.0.1:45001").value();
    const auto routed_claim = parse_endpoint("198.51.100.7:45001").value();
    CHECK_FALSE(claim_fits_relay(loopback_claim, remote_relay));
    CHECK_FALSE(claim_fits_relay(parse_endpoint("[::1]:45001").value(), remote_relay));
    CHECK(claim_fits_relay(loopback_claim, local_relay));
    CHECK(claim_fits_relay(routed_claim, remote_relay));
}

TEST_CASE("Endpoints need brackets around IPv6 addresses and a numeric port") {
    CHECK(parse_endpoint("127.0.0.1:3333").value().address.family == AF_INET);
    CHECK(parse_endpoint("[::1]:3333").value().address.family == AF_INET6);
    constexpr std::array<std::string_view, 6> rejected{
        "::1:3333", "127.0.0.1", "127.0.0.1:65536", "localhost:3333", "[127.0.0.1]:3333",
        "127.0.0.1:-1",
    };
    for (const auto text : rejected)
        CHECK_FALSE(parse_endpoint(text).has_value());
}

TEST_CASE("Transparent sources must be concrete unicast tuples") {
    CHECK(usable_transparent_source(parse_endpoint("192.0.2.20:1").value()));
    CHECK(usable_transparent_source(parse_endpoint("[2001:db8::1]:1").value()));
    constexpr std::array<std::string_view, 8> unusable{
        "192.0.2.20:0", "0.0.0.0:1", "224.0.0.1:1", "255.255.255.255:1",
        "[::]:1", "[ff02::1]:1", "[fe80::1]:1", "[::ffff:192.0.2.20]:1",
    };
    for (const auto text : unusable)
        CHECK_FALSE(usable_transparent_source(parse_endpoint(text).value()));
}

TEST_CASE("IPv4-mapped addresses unmap to IPv4, and other addresses stay unchanged") {
    const auto mapped = parse_ip_address("::ffff:192.0.2.20").value();
    CHECK(unmap_ipv4(mapped) == parse_ip_address("192.0.2.20").value());
    const auto ipv6 = parse_ip_address("2001:db8::20").value();
    CHECK(unmap_ipv4(ipv6) == ipv6);
    const auto ipv4 = parse_ip_address("192.0.2.20").value();
    CHECK(unmap_ipv4(ipv4) == ipv4);
}

TEST_CASE("Client sources are IPv4 addresses and IPv6 /64 networks") {
    const auto ipv4 = parse_ip_address("192.0.2.20").value();
    CHECK(client_source(ipv4) == ipv4);
    CHECK(client_source(parse_ip_address("::ffff:192.0.2.20").value()) == ipv4);
    CHECK(client_source(parse_ip_address("2001:db8:1:2:aaaa::1").value()) ==
          parse_ip_address("2001:db8:1:2::").value());
    // NAT64 clients count by the IPv4 address they carry, not as one shared /64.
    CHECK(client_source(parse_ip_address("64:ff9b::192.0.2.20").value()) == ipv4);
}

TEST_CASE("Socket addresses round-trip, and mapped kernel peers read back as IPv4") {
    for (const auto text : {"192.0.2.20:12345", "[2001:db8::20]:443"}) {
        const auto endpoint = parse_endpoint(text).value();
        const auto socket_address = to_socket_address(endpoint);
        CHECK(from_socket_address(socket_address.storage) == endpoint);
    }
    const auto mapped = to_socket_address(parse_endpoint("[::ffff:192.0.2.20]:12345").value());
    CHECK(from_socket_address(mapped.storage) == parse_endpoint("192.0.2.20:12345").value());
}

} // namespace
} // namespace erikslund::mmproxy
