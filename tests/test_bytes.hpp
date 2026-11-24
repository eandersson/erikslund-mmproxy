#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace erikslund::mmproxy {

inline std::span<const std::uint8_t> bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

} // namespace erikslund::mmproxy
