#pragma once

#include <charconv>
#include <concepts>
#include <optional>
#include <string_view>
#include <system_error>

namespace erikslund::mmproxy {

template <std::integral Number>
[[nodiscard]] std::optional<Number> parse_number(std::string_view text) noexcept {
    Number number{};
    const auto [next, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    if (error != std::errc{} || next != text.data() + text.size())
        return std::nullopt;
    return number;
}

} // namespace erikslund::mmproxy
