#include <doctest/doctest.h>

#include <string>

#include "mmproxy/fair_share.hpp"

namespace erikslund::mmproxy {
namespace {

// 64 slots: contention starts at 56 in use, and a source may then hold at most 4.
constexpr std::size_t kCapacity = 64;
constexpr std::size_t kContendedAt = 56;
constexpr std::size_t kShare = 4;

IpAddress address(const std::string& text) {
    return parse_ip_address(text).value();
}

TEST_CASE("One source may fill an uncontended proxy, but not the last eighth") {
    FairShare fair_share(kCapacity);
    const auto large = address("198.51.100.7");
    for (std::size_t held = 0; held < kContendedAt; ++held)
        REQUIRE(fair_share.admit(large));
    CHECK_FALSE(fair_share.admit(large));

    // Smaller sources still get the reserved slots, each up to its share.
    const auto small = address("203.0.113.9");
    for (std::size_t held = 0; held < kShare; ++held)
        CHECK(fair_share.admit(small));
    CHECK_FALSE(fair_share.admit(small));
    CHECK(fair_share.admit(address("203.0.113.10")));
}

TEST_CASE("Released connections lift a source back under contention") {
    FairShare fair_share(kCapacity);
    const auto large = address("198.51.100.7");
    for (std::size_t held = 0; held < kContendedAt; ++held)
        REQUIRE(fair_share.admit(large));
    REQUIRE_FALSE(fair_share.admit(large));
    fair_share.release(large);
    CHECK(fair_share.admit(large));
}

TEST_CASE("An IPv6 /64 counts as one source") {
    FairShare fair_share(kCapacity);
    for (std::size_t host = 1; host <= kContendedAt; ++host)
        REQUIRE(fair_share.admit(address("2001:db8:1:2::" + std::to_string(host))));
    CHECK_FALSE(fair_share.admit(address("2001:db8:1:2:ffff::1")));
    CHECK(fair_share.admit(address("2001:db8:1:3::1")));
}

} // namespace
} // namespace erikslund::mmproxy
