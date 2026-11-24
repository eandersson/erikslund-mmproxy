#include <doctest/doctest.h>

#include <utility>

#include <sys/eventfd.h>

#include "mmproxy/balancer.hpp"

namespace erikslund::mmproxy {
namespace {

constexpr std::size_t kWorkers = 3;

TEST_CASE("The accepting worker keeps a client unless another worker holds fewer") {
    Balancer balancer(kWorkers);
    CHECK(balancer.choose(0) == 0);
    CHECK(balancer.choose(2) == 2);

    balancer.opened(0);
    balancer.opened(0);
    balancer.opened(1);
    CHECK(balancer.choose(0) == 2);
    CHECK(balancer.choose(2) == 2);

    balancer.opened(2);
    balancer.opened(2);
    CHECK(balancer.choose(0) == 1);
    balancer.closed(0);
    balancer.closed(0);
    CHECK(balancer.choose(1) == 0);
}

TEST_CASE("A handed-off client counts at once and reaches the target's inbox") {
    Balancer balancer(kWorkers);
    balancer.opened(0);
    const int marker = ::eventfd(0, EFD_CLOEXEC);
    REQUIRE(marker >= 0);
    balancer.hand_off(1, Handoff{.client = FileDescriptor(marker), .relay = {}});

    // Worker 1 now counts the client, so a second accept on worker 0 picks worker 2.
    CHECK(balancer.choose(0) == 2);
    auto handoffs = balancer.take_handoffs(1);
    REQUIRE(handoffs.size() == 1);
    CHECK(handoffs.front().client.get() == marker);
    CHECK(balancer.take_handoffs(1).empty());
    CHECK(balancer.take_handoffs(2).empty());
}

} // namespace
} // namespace erikslund::mmproxy
