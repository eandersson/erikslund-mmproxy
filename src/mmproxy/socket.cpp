#include "mmproxy/socket.hpp"

#include <cerrno>
#include <format>
#include <system_error>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

namespace erikslund::mmproxy {
namespace {

constexpr int kProxyBacklog = 4096;
constexpr int kNotSentLowWaterBytes = 1 << 20;
constexpr int kKeepAliveIdleSeconds = 60;
constexpr int kKeepAliveIntervalSeconds = 10;
constexpr int kKeepAliveProbes = 6;

bool set_option(int descriptor, int level, int option, int value = 1) {
    return ::setsockopt(descriptor, level, option, &value, sizeof(value)) == 0;
}

bool set_transparent(int descriptor, int family) {
    if (family == AF_INET)
        return set_option(descriptor, IPPROTO_IP, IP_TRANSPARENT);
    return set_option(descriptor, IPPROTO_IPV6, IPV6_TRANSPARENT);
}

FileDescriptor make_bound_socket(const Endpoint& endpoint, int socket_type, bool reuse_port) {
    const int family = endpoint.address.family;
    FileDescriptor socket(::socket(family, socket_type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!socket)
        throw_system_error("create listener socket");
    if (socket_type == SOCK_STREAM && !set_option(socket.get(), SOL_SOCKET, SO_REUSEADDR))
        throw_system_error("set listener SO_REUSEADDR");
    if (reuse_port && !set_option(socket.get(), SOL_SOCKET, SO_REUSEPORT))
        throw_system_error("set listener SO_REUSEPORT");
    if (family == AF_INET6 && !set_option(socket.get(), IPPROTO_IPV6, IPV6_V6ONLY))
        throw_system_error("set listener IPV6_V6ONLY");
    if (socket_type == SOCK_DGRAM) {
        const bool enabled = family == AF_INET ? set_option(socket.get(), IPPROTO_IP, IP_PKTINFO) :
            set_option(socket.get(), IPPROTO_IPV6, IPV6_RECVPKTINFO);
        if (!enabled)
            throw_system_error("enable UDP packet information");
    }
    const auto address = to_socket_address(endpoint);
    if (::bind(socket.get(), address.data(), address.length) != 0)
        throw_system_error("bind proxy listener");
    return socket;
}

int socket_type_for(Transport transport) {
    return transport == Transport::Tcp ? SOCK_STREAM : SOCK_DGRAM;
}

} // namespace

[[noreturn]] void throw_system_error(const char* operation) {
    const std::error_code error(errno, std::generic_category());
    throw SystemError(std::format("{}: {}", operation, error.message()));
}

bool is_retryable(int error) noexcept {
    return error == EAGAIN || error == EWOULDBLOCK || error == EINTR;
}

FileDescriptor make_listener(const Config& config) {
    const int socket_type = socket_type_for(config.transport);
    auto socket = make_bound_socket(config.listen, socket_type, config.workers > 1);
    if (socket_type == SOCK_STREAM) {
        if (!set_option(socket.get(), IPPROTO_TCP, TCP_NODELAY))
            throw_system_error("set listener TCP_NODELAY");
        if (!set_option(socket.get(), IPPROTO_TCP, TCP_NOTSENT_LOWAT, kNotSentLowWaterBytes))
            throw_system_error("set listener TCP_NOTSENT_LOWAT");
        if (!set_option(socket.get(), SOL_SOCKET, SO_OOBINLINE))
            throw_system_error("set listener SO_OOBINLINE");
        if (!set_option(socket.get(), SOL_SOCKET, SO_KEEPALIVE) ||
            !set_option(socket.get(), IPPROTO_TCP, TCP_KEEPIDLE, kKeepAliveIdleSeconds) ||
            !set_option(socket.get(), IPPROTO_TCP, TCP_KEEPINTVL, kKeepAliveIntervalSeconds) ||
            !set_option(socket.get(), IPPROTO_TCP, TCP_KEEPCNT, kKeepAliveProbes))
            throw_system_error("enable listener keepalive");
        if (const auto timeout = static_cast<int>(config.user_timeout.count());
            timeout != 0 && !set_option(socket.get(), IPPROTO_TCP, TCP_USER_TIMEOUT, timeout))
            throw_system_error("set listener TCP_USER_TIMEOUT");
        if (::listen(socket.get(), kProxyBacklog) != 0)
            throw_system_error("listen for TCP proxy connections");
    }
    return socket;
}

std::expected<FileDescriptor, BackendFailure>
open_backend_socket(const Config& config, const Endpoint& backend,
                    const std::optional<Endpoint>& source, int socket_type) {
    const int family = backend.address.family;
    if (source && *source == backend)
        return std::unexpected(BackendFailure::Bind);
    FileDescriptor socket(::socket(family, socket_type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!socket)
        return std::unexpected(BackendFailure::Setup);
    if (config.backend_mark != 0 &&
        !set_option(socket.get(), SOL_SOCKET, SO_MARK, config.backend_mark))
        return std::unexpected(BackendFailure::Setup);
    if (socket_type == SOCK_STREAM &&
        (!set_option(socket.get(), IPPROTO_TCP, TCP_NODELAY) ||
         !set_option(socket.get(), IPPROTO_TCP, TCP_NOTSENT_LOWAT, kNotSentLowWaterBytes) ||
         !set_option(socket.get(), SOL_SOCKET, SO_OOBINLINE)))
        return std::unexpected(BackendFailure::Setup);
    if (source) {
        if (!set_transparent(socket.get(), family))
            return std::unexpected(BackendFailure::Setup);
        if (socket_type == SOCK_STREAM && !set_option(socket.get(), SOL_SOCKET, SO_REUSEADDR))
            return std::unexpected(BackendFailure::Setup);
        const auto local = to_socket_address(*source);
        if (::bind(socket.get(), local.data(), local.length) != 0)
            return std::unexpected(BackendFailure::Bind);
    }
    return socket;
}

void check_backend_permissions(const Config& config) {
    const int socket_type = socket_type_for(config.transport);
    for (const auto* backend : {&config.backend_ipv4, &config.backend_ipv6}) {
        if (!*backend)
            continue;
        const int family = (*backend)->address.family;
        FileDescriptor socket(::socket(family, socket_type | SOCK_CLOEXEC, 0));
        if (!socket)
            throw_system_error("create backend test socket");
        if (!set_transparent(socket.get(), family))
            throw_system_error(
                "enable transparent backend sockets (requires CAP_NET_RAW or CAP_NET_ADMIN)");
        if (config.backend_mark != 0 &&
            !set_option(socket.get(), SOL_SOCKET, SO_MARK, config.backend_mark))
            throw_system_error("set backend socket mark");
    }
}

} // namespace erikslund::mmproxy
