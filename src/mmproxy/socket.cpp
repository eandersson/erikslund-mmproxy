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
        throw_socket_error("create listener socket");
    if (socket_type == SOCK_STREAM && !set_option(socket.get(), SOL_SOCKET, SO_REUSEADDR))
        throw_socket_error("set listener SO_REUSEADDR");
    if (reuse_port && !set_option(socket.get(), SOL_SOCKET, SO_REUSEPORT))
        throw_socket_error("set listener SO_REUSEPORT");
    if (family == AF_INET6 && !set_option(socket.get(), IPPROTO_IPV6, IPV6_V6ONLY))
        throw_socket_error("set listener IPV6_V6ONLY");
    if (socket_type == SOCK_DGRAM) {
        const bool enabled = family == AF_INET ? set_option(socket.get(), IPPROTO_IP, IP_PKTINFO) :
            set_option(socket.get(), IPPROTO_IPV6, IPV6_RECVPKTINFO);
        if (!enabled)
            throw_socket_error("enable UDP packet information");
    }
    const auto address = to_socket_address(endpoint);
    if (::bind(socket.get(), address.data(), address.length) != 0)
        throw_socket_error("bind proxy listener");
    return socket;
}

} // namespace

[[noreturn]] void throw_socket_error(const char* operation) {
    const std::error_code error(errno, std::generic_category());
    throw SocketError(std::format("{}: {}", operation, error.message()));
}

FileDescriptor make_listener(const Config& config, int socket_type) {
    auto socket = make_bound_socket(config.listen, socket_type, config.workers > 1);
    if (socket_type == SOCK_STREAM) {
        if (!set_option(socket.get(), IPPROTO_TCP, TCP_NODELAY))
            throw_socket_error("set listener TCP_NODELAY");
        if (!set_option(socket.get(), IPPROTO_TCP, TCP_NOTSENT_LOWAT, kNotSentLowWaterBytes))
            throw_socket_error("set listener TCP_NOTSENT_LOWAT");
        if (!set_option(socket.get(), SOL_SOCKET, SO_OOBINLINE))
            throw_socket_error("set listener SO_OOBINLINE");
        if (!set_option(socket.get(), SOL_SOCKET, SO_KEEPALIVE) ||
            !set_option(socket.get(), IPPROTO_TCP, TCP_KEEPIDLE, kKeepAliveIdleSeconds) ||
            !set_option(socket.get(), IPPROTO_TCP, TCP_KEEPINTVL, kKeepAliveIntervalSeconds) ||
            !set_option(socket.get(), IPPROTO_TCP, TCP_KEEPCNT, kKeepAliveProbes))
            throw_socket_error("enable listener keepalive");
        if (const auto timeout = static_cast<int>(config.user_timeout.count());
            timeout != 0 && !set_option(socket.get(), IPPROTO_TCP, TCP_USER_TIMEOUT, timeout))
            throw_socket_error("set listener TCP_USER_TIMEOUT");
        if (::listen(socket.get(), kProxyBacklog) != 0)
            throw_socket_error("listen for TCP proxy connections");
    }
    return socket;
}

std::expected<FileDescriptor, UpstreamFailure>
open_upstream(const Config& config, const Endpoint& backend, const std::optional<Endpoint>& source,
              int socket_type) {
    const int family = backend.address.family;
    if (source && *source == backend)
        return std::unexpected(UpstreamFailure::Bind);
    FileDescriptor socket(::socket(family, socket_type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!socket)
        return std::unexpected(UpstreamFailure::Setup);
    if (config.mark != 0 && !set_option(socket.get(), SOL_SOCKET, SO_MARK, config.mark))
        return std::unexpected(UpstreamFailure::Setup);
    if (socket_type == SOCK_STREAM &&
        (!set_option(socket.get(), IPPROTO_TCP, TCP_NODELAY) ||
         !set_option(socket.get(), IPPROTO_TCP, TCP_NOTSENT_LOWAT, kNotSentLowWaterBytes) ||
         !set_option(socket.get(), SOL_SOCKET, SO_OOBINLINE)))
        return std::unexpected(UpstreamFailure::Setup);
    if (source) {
        if (!set_transparent(socket.get(), family))
            return std::unexpected(UpstreamFailure::Setup);
        if (socket_type == SOCK_STREAM && !set_option(socket.get(), SOL_SOCKET, SO_REUSEADDR))
            return std::unexpected(UpstreamFailure::Setup);
        const auto local = to_socket_address(*source);
        if (::bind(socket.get(), local.data(), local.length) != 0)
            return std::unexpected(UpstreamFailure::Bind);
    }
    return socket;
}

void check_upstream_permissions(const Config& config) {
    const int socket_type = config.transport == Transport::Tcp ? SOCK_STREAM : SOCK_DGRAM;
    for (const auto* backend : {&config.backend_ipv4, &config.backend_ipv6}) {
        if (!*backend)
            continue;
        const int family = (*backend)->address.family;
        FileDescriptor socket(::socket(family, socket_type | SOCK_CLOEXEC, 0));
        if (!socket)
            throw_socket_error("create backend test socket");
        if (!set_transparent(socket.get(), family))
            throw_socket_error(
                "enable transparent backend sockets (requires CAP_NET_RAW or CAP_NET_ADMIN)");
        if (config.mark != 0 && !set_option(socket.get(), SOL_SOCKET, SO_MARK, config.mark))
            throw_socket_error("set backend socket mark");
    }
}

} // namespace erikslund::mmproxy
