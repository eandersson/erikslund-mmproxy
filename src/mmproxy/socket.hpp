#pragma once
// Create proxy listeners and transparent backend sockets.

#include <expected>
#include <optional>
#include <stdexcept>

#include "mmproxy/config.hpp"
#include "mmproxy/file_descriptor.hpp"
#include "mmproxy/metrics.hpp"

namespace erikslund::mmproxy {

class SystemError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void throw_system_error(const char* operation);
[[nodiscard]] bool is_retryable(int error) noexcept;
[[nodiscard]] FileDescriptor make_listener(const Config& config);

[[nodiscard]] std::expected<FileDescriptor, BackendFailure>
open_backend_socket(const Config& config, const Endpoint& backend,
                    const std::optional<Endpoint>& source, int socket_type);

void check_backend_permissions(const Config& config);

} // namespace erikslund::mmproxy
