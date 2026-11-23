#pragma once
// Create proxy listeners and transparent upstream sockets.

#include <expected>
#include <optional>
#include <stdexcept>

#include "mmproxy/config.hpp"
#include "mmproxy/file_descriptor.hpp"
#include "mmproxy/metrics.hpp"

namespace erikslund::mmproxy {

class SocketError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void throw_socket_error(const char* operation);
[[nodiscard]] FileDescriptor make_listener(const Config& config, int socket_type);

[[nodiscard]] std::expected<FileDescriptor, UpstreamFailure>
open_upstream(const Config& config, const Endpoint& backend, const std::optional<Endpoint>& source,
              int socket_type);

void check_upstream_permissions(const Config& config);

} // namespace erikslund::mmproxy
