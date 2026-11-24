#include <doctest/doctest.h>

#include <cstdint>

#include "mmproxy/number.hpp"

namespace erikslund::mmproxy {
namespace {

TEST_CASE("parse_number accepts only a whole number that fits the type") {
    CHECK(parse_number<int>("42") == 42);
    CHECK(parse_number<int>("-7") == -7);
    CHECK(parse_number<std::uint16_t>("65535") == 65535);
    for (const auto text : {"", " 4", "4 ", "4x", "0x10", "+4"})
        CHECK_FALSE(parse_number<int>(text).has_value());
    CHECK_FALSE(parse_number<std::uint16_t>("65536").has_value());
    CHECK_FALSE(parse_number<unsigned int>("-1").has_value());
}

} // namespace
} // namespace erikslund::mmproxy
