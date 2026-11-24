#include "mmproxy/udp.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <compare>
#include <cstdint>
#include <cstring>
#include <expected>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "mmproxy/address.hpp"
#include "mmproxy/proxy_protocol.hpp"

namespace erikslund::mmproxy {
namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

constexpr std::size_t kMaxPacketBytes = 65'535;
constexpr std::size_t kEventBatchSize = 64;
constexpr std::size_t kPacketsPerEvent = 32;
constexpr auto kStopCheckInterval = 250ms;
constexpr std::uint64_t kListenerToken = 0;
constexpr unsigned kSlotIdBits = 32;
constexpr std::size_t kPacketInfoBytes = CMSG_SPACE(sizeof(in6_pktinfo));
constexpr auto kMinClientSilenceLimit = std::chrono::minutes(5);

struct ReplyPath {
    Endpoint relay;
    IpAddress local_address;
    std::uint32_t interface_index{};

    auto operator<=>(const ReplyPath&) const = default;
};

struct FlowKey {
    bool transparent;
    Endpoint endpoint;

    auto operator<=>(const FlowKey&) const = default;
};

using IdleOrder = std::list<std::size_t>;
using FlowsByNetwork = std::map<IpAddress, IdleOrder>;

struct Flow {
    FileDescriptor backend;
    FlowKey key{};
    ReplyPath reply_path{};
    IdleOrder::iterator idle_position;
    Clock::time_point deadline{};
    FlowsByNetwork::iterator network_entry;
    IdleOrder::iterator network_position;
    Clock::time_point last_client{};
    std::uint32_t generation{};
};

template <typename PacketInfo>
PacketInfo copy_packet_info(cmsghdr* header) {
    PacketInfo info{};
    std::memcpy(&info, CMSG_DATA(header), sizeof(info));
    return info;
}

std::optional<ReplyPath> read_reply_path(msghdr& message, const Endpoint& relay) {
    ReplyPath path{.relay = relay, .local_address = {.family = relay.address.family, .bytes = {}}};

    for (auto* header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        if (relay.address.family == AF_INET && header->cmsg_level == IPPROTO_IP &&
            header->cmsg_type == IP_PKTINFO && header->cmsg_len >= CMSG_LEN(sizeof(in_pktinfo))) {
            const auto info = copy_packet_info<in_pktinfo>(header);
            std::memcpy(path.local_address.bytes.data(), &info.ipi_spec_dst,
                        sizeof(info.ipi_spec_dst));
            return path;
        }

        if (relay.address.family == AF_INET6 && header->cmsg_level == IPPROTO_IPV6 &&
            header->cmsg_type == IPV6_PKTINFO &&
            header->cmsg_len >= CMSG_LEN(sizeof(in6_pktinfo))) {
            const auto info = copy_packet_info<in6_pktinfo>(header);
            std::memcpy(path.local_address.bytes.data(), &info.ipi6_addr, sizeof(info.ipi6_addr));
            if (IN6_IS_ADDR_LINKLOCAL(&info.ipi6_addr))
                path.interface_index = info.ipi6_ifindex;
            return path;
        }
    }

    return std::nullopt;
}

template <typename PacketInfo>
void set_packet_info(msghdr& message, int level, int type, const PacketInfo& info) {
    message.msg_controllen = CMSG_SPACE(sizeof(info));
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = level;
    header->cmsg_type = type;
    header->cmsg_len = CMSG_LEN(sizeof(info));
    std::memcpy(CMSG_DATA(header), &info, sizeof(info));
}

ssize_t send_reply(int listener_fd, const ReplyPath& path, std::span<std::uint8_t> payload) {
    auto relay = to_socket_address(path.relay);
    iovec bytes{.iov_base = payload.data(), .iov_len = payload.size()};
    alignas(cmsghdr) std::array<unsigned char, kPacketInfoBytes> control{};
    msghdr message{};
    message.msg_name = &relay.storage;
    message.msg_namelen = relay.length;
    message.msg_iov = &bytes;
    message.msg_iovlen = 1;
    message.msg_control = control.data();

    // A connected relay expects replies from the local address it sent to.
    if (path.local_address.family == AF_INET) {
        in_pktinfo info{};
        std::memcpy(&info.ipi_spec_dst, path.local_address.bytes.data(), sizeof(info.ipi_spec_dst));
        set_packet_info(message, IPPROTO_IP, IP_PKTINFO, info);
    } else {
        in6_pktinfo info{};
        std::memcpy(&info.ipi6_addr, path.local_address.bytes.data(), sizeof(info.ipi6_addr));
        info.ipi6_ifindex = path.interface_index;
        set_packet_info(message, IPPROTO_IPV6, IPV6_PKTINFO, info);
    }

    return ::sendmsg(listener_fd, &message, MSG_NOSIGNAL);
}

std::uint64_t flow_token(std::size_t slot, std::uint32_t generation) {
    return (static_cast<std::uint64_t>(generation) << kSlotIdBits) | (slot + 1);
}

class UdpWorker {
public:
    UdpWorker(const Config& config, FileDescriptor listener, std::size_t flow_limit,
              Metrics& metrics)
        : config_(config), listener_(std::move(listener)), metrics_(metrics),
          poller_(::epoll_create1(EPOLL_CLOEXEC)),
          client_silence_limit_(
              std::max<Clock::duration>(config.udp_timeout, kMinClientSilenceLimit)) {
        if (!poller_)
            throw_system_error("create UDP poller");
        if (!register_socket(listener_.get(), kListenerToken))
            throw_system_error("register UDP listener");

        flows_.resize(flow_limit);
        free_slots_.reserve(flow_limit);
        for (std::size_t remaining = flow_limit; remaining > 0; --remaining)
            free_slots_.push_back(remaining - 1);
    }

    ~UdpWorker() {
        metrics_.active.fetch_sub(idle_order_.size(), std::memory_order_relaxed);
    }

    UdpWorker(const UdpWorker&) = delete;
    UdpWorker& operator=(const UdpWorker&) = delete;

    void run(const std::stop_token& stop) {
        std::array<epoll_event, kEventBatchSize> events{};
        while (!stop.stop_requested()) {
            const auto now = Clock::now();
            expire_flows(now);
            const int ready = ::epoll_wait(poller_.get(), events.data(),
                                           static_cast<int>(events.size()), wait_timeout(now));
            if (ready < 0) {
                if (errno == EINTR)
                    continue;
                throw_system_error("poll UDP sockets");
            }

            expire_flows(Clock::now());
            for (int event_index = 0; event_index < ready && !stop.stop_requested(); ++event_index)
                dispatch(events[static_cast<std::size_t>(event_index)]);
        }
    }

private:
    bool register_socket(int socket_fd, std::uint64_t token) const {
        epoll_event event{};
        event.events = EPOLLIN;
        event.data.u64 = token;
        return ::epoll_ctl(poller_.get(), EPOLL_CTL_ADD, socket_fd, &event) == 0;
    }

    void dispatch(const epoll_event& event) {
        const std::uint64_t token = event.data.u64;
        if (token == kListenerToken) {
            if ((event.events & EPOLLIN) != 0)
                receive_client_packets();
            if ((event.events & EPOLLERR) != 0)
                clear_listener_error();
            return;
        }

        const auto slot_id = static_cast<std::uint32_t>(token);
        const auto generation = static_cast<std::uint32_t>(token >> kSlotIdBits);
        if (slot_id == 0 || slot_id > flows_.size())
            return;

        const auto slot = static_cast<std::size_t>(slot_id - 1);
        auto& flow = flows_[slot];
        if (flow.backend && flow.generation == generation)
            receive_backend_packets(slot);
    }

    void clear_listener_error() const {
        int socket_error{};
        socklen_t error_bytes = sizeof(socket_error);
        if (::getsockopt(listener_.get(), SOL_SOCKET, SO_ERROR, &socket_error, &error_bytes) < 0)
            throw_system_error("clear UDP listener error");
    }

    int wait_timeout(Clock::time_point now) const {
        if (idle_order_.empty())
            return static_cast<int>(kStopCheckInterval.count());

        const auto wait = std::chrono::ceil<std::chrono::milliseconds>(
            flows_[idle_order_.front()].deadline - now);
        return static_cast<int>(std::clamp(wait, 0ms, kStopCheckInterval).count());
    }

    void expire_flows(Clock::time_point now) {
        while (!idle_order_.empty() && flows_[idle_order_.front()].deadline <= now) {
            close_flow(idle_order_.front());
            metrics_.count_timeout(TimeoutPhase::Idle);
        }
    }

    void close_flow(std::size_t slot) {
        auto& flow = flows_[slot];
        flow_index_.erase(flow.key);
        idle_order_.erase(flow.idle_position);
        leave_network(flow);
        flow.backend.reset();
        free_slots_.push_back(slot);
        metrics_.active.fetch_sub(1, std::memory_order_relaxed);
    }

    void join_network(std::size_t slot, const IpAddress& network) {
        auto& flow = flows_[slot];
        flow.network_entry = flows_by_network_.try_emplace(network).first;
        auto& order = flow.network_entry->second;
        if (!order.empty())
            networks_by_flow_count_.erase({order.size(), network});
        order.push_back(slot);
        flow.network_position = std::prev(order.end());
        networks_by_flow_count_.emplace(order.size(), network);
    }

    void leave_network(const Flow& flow) {
        const auto network = flow.network_entry->first;
        auto& order = flow.network_entry->second;
        networks_by_flow_count_.erase({order.size(), network});
        order.erase(flow.network_position);
        if (order.empty())
            flows_by_network_.erase(flow.network_entry);
        else
            networks_by_flow_count_.emplace(order.size(), network);
    }

    [[nodiscard]] bool may_evict_for(const IpAddress& network) const {
        if (networks_by_flow_count_.empty())
            return false;
        const auto largest_count = networks_by_flow_count_.rbegin()->first;
        const auto held = flows_by_network_.find(network);
        return held == flows_by_network_.end() || held->second.size() < largest_count;
    }

    void evict_for_newcomer() {
        const auto [largest_count, largest_network] = *networks_by_flow_count_.rbegin();
        const auto victim = largest_count > 1 ?
                                flows_by_network_.find(largest_network)->second.front() :
                                idle_order_.front();
        close_flow(victim);
        increment(metrics_.flows_evicted);
    }

    void refresh(Flow& flow, Clock::time_point now) {
        flow.deadline = now + config_.udp_timeout;
        idle_order_.splice(idle_order_.end(), idle_order_, flow.idle_position);
    }

    void refresh_client(Flow& flow, Clock::time_point now) {
        refresh(flow, now);
        flow.last_client = now;
        auto& order = flow.network_entry->second;
        order.splice(order.end(), order, flow.network_position);
    }

    void count_drop() const {
        increment(metrics_.udp_dropped);
    }

    void receive_client_packets() {
        for (std::size_t packet = 0; packet < kPacketsPerEvent; ++packet) {
            sockaddr_storage relay_address{};
            alignas(cmsghdr) std::array<unsigned char, kPacketInfoBytes> control{};
            iovec bytes{.iov_base = packet_.data(), .iov_len = packet_.size()};
            msghdr message{};
            message.msg_name = &relay_address;
            message.msg_namelen = sizeof(relay_address);
            message.msg_iov = &bytes;
            message.msg_iovlen = 1;
            message.msg_control = control.data();
            message.msg_controllen = control.size();

            const auto received = ::recvmsg(listener_.get(), &message, MSG_TRUNC);
            if (received < 0) {
                if (errno == EINTR)
                    continue;
                return;
            }

            const auto size = static_cast<std::size_t>(received);
            if (size > packet_.size() || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
                count_drop();
                continue;
            }
            handle_client_packet(relay_address, message, std::span(packet_).first(size));
        }
    }

    void handle_client_packet(const sockaddr_storage& relay_address, msghdr& message,
                              std::span<const std::uint8_t> bytes) {
        const auto relay = from_socket_address(relay_address);
        if (!relay || !config_.trusted.contains(relay->address)) {
            increment(metrics_.untrusted);
            count_drop();
            return;
        }

        const auto header = parse_proxy_header(bytes, ProxyTransport::Datagram);
        if (!header || !relay_may_claim(*relay, header->source)) {
            increment(metrics_.invalid_header);
            count_drop();
            return;
        }

        const auto reply_path = read_reply_path(message, *relay);
        if (!reply_path) {
            count_drop();
            return;
        }

        const FlowKey key{.transparent = header->source.has_value(),
                          .endpoint = header->source.value_or(*relay)};
        const auto now = Clock::now();
        const auto slot = find_or_open_flow(key, *reply_path, header->source, now);
        if (!slot) {
            count_drop();
            return;
        }
        forward_to_backend(*slot, bytes.subspan(header->size), now);
    }

    void forward_to_backend(std::size_t slot, std::span<const std::uint8_t> payload,
                            Clock::time_point now) {
        auto& flow = flows_[slot];
        const auto sent = ::send(flow.backend.get(), payload.data(), payload.size(), MSG_NOSIGNAL);
        if (sent < 0) {
            if (!is_retryable(errno)) {
                metrics_.count_backend_failure(BackendFailure::Forwarding);
                close_flow(slot);
            }
            count_drop();
            return;
        }
        increment(metrics_.client_to_backend_bytes, static_cast<std::uint64_t>(sent));
        refresh_client(flow, now);
    }

    std::optional<std::size_t> find_or_open_flow(const FlowKey& key, const ReplyPath& path,
                                                 const std::optional<Endpoint>& claimed_source,
                                                 Clock::time_point now) {
        if (const auto existing = flow_index_.find(key); existing != flow_index_.end()) {
            if (flows_[existing->second].reply_path != path)
                return std::nullopt;
            return existing->second;
        }

        const auto network = client_network(key.endpoint.address);
        const bool full = free_slots_.empty();
        if (full && !may_evict_for(network)) {
            increment(metrics_.limit_reached);
            return std::nullopt;
        }
        auto backend = connect_backend(key.endpoint.address.family, claimed_source);
        if (!backend) {
            metrics_.count_backend_failure(backend.error());
            return std::nullopt;
        }
        if (full)
            evict_for_newcomer();
        return install_flow(std::move(*backend), key, path, network, now);
    }

    std::expected<FileDescriptor, BackendFailure>
    connect_backend(int family, const std::optional<Endpoint>& claimed_source) const {
        const auto& backend = backend_for(config_, family);
        if (!backend)
            return std::unexpected(BackendFailure::NoBackend);
        auto socket = open_backend_socket(config_, *backend, claimed_source, SOCK_DGRAM);
        if (!socket)
            return socket;
        const auto destination = to_socket_address(*backend);
        if (::connect(socket->get(), destination.data(), destination.length) < 0)
            return std::unexpected(BackendFailure::Connect);
        return socket;
    }

    std::optional<std::size_t> install_flow(FileDescriptor backend, const FlowKey& key,
                                            const ReplyPath& path, const IpAddress& network,
                                            Clock::time_point now) {
        const auto slot = free_slots_.back();
        auto& flow = flows_[slot];
        ++flow.generation;
        if (!register_socket(backend.get(), flow_token(slot, flow.generation))) {
            metrics_.count_backend_failure(BackendFailure::Setup);
            return std::nullopt;
        }

        flow_index_.emplace(key, slot);
        idle_order_.push_back(slot);
        flow.idle_position = std::prev(idle_order_.end());
        join_network(slot, network);
        flow.key = key;
        flow.reply_path = path;
        flow.backend = std::move(backend);
        free_slots_.pop_back();
        increment(metrics_.active);
        increment(metrics_.accepted);
        refresh_client(flow, now);
        return slot;
    }

    void receive_backend_packets(std::size_t slot) {
        auto& flow = flows_[slot];
        const auto now = Clock::now();
        if (now - flow.last_client > client_silence_limit_) {
            close_flow(slot);
            metrics_.count_timeout(TimeoutPhase::Idle);
            return;
        }
        for (std::size_t packet = 0; packet < kPacketsPerEvent; ++packet) {
            const auto received = ::recv(flow.backend.get(), packet_.data(), packet_.size(),
                                         MSG_TRUNC);
            if (received < 0) {
                const int error = errno;
                if (error == EINTR)
                    continue;
                if (!is_retryable(error)) {
                    metrics_.count_backend_failure(BackendFailure::Forwarding);
                    close_flow(slot);
                }
                return;
            }

            const auto size = static_cast<std::size_t>(received);
            if (size > packet_.size()) {
                count_drop();
                continue;
            }

            const auto sent = send_reply(listener_.get(), flow.reply_path,
                                         std::span(packet_).first(size));
            if (sent < 0) {
                count_drop();
                continue;
            }

            increment(metrics_.backend_to_client_bytes, static_cast<std::uint64_t>(sent));
            refresh(flow, now);
        }
    }

    const Config& config_;
    FileDescriptor listener_;
    Metrics& metrics_;
    FileDescriptor poller_;
    std::vector<Flow> flows_;
    std::vector<std::size_t> free_slots_;
    std::map<FlowKey, std::size_t> flow_index_;
    IdleOrder idle_order_;
    FlowsByNetwork flows_by_network_;
    std::set<std::pair<std::size_t, IpAddress>> networks_by_flow_count_;
    Clock::duration client_silence_limit_;
    std::array<std::uint8_t, kMaxPacketBytes> packet_{};
};

} // namespace

void run_udp(const std::stop_token& stop, const Config& config, FileDescriptor listener,
             std::size_t flow_limit, Metrics& metrics) {
    if (flow_limit > std::numeric_limits<std::uint32_t>::max())
        throw ConfigError("UDP flow limit exceeds the worker slot index");

    UdpWorker worker(config, std::move(listener), flow_limit, metrics);
    worker.run(stop);
}

} // namespace erikslund::mmproxy
