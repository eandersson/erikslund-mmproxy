#include "mmproxy/tcp.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <optional>
#include <ranges>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mmproxy/proxy_protocol.hpp"

namespace erikslund::mmproxy {
namespace {

using Clock = std::chrono::steady_clock;
using ConnectionId = std::uint64_t;
using DeadlineQueue = std::list<ConnectionId>;

constexpr std::size_t kInitialHeaderBytes = 512;
constexpr std::size_t kScratchBytes = 64 << 10;
constexpr std::size_t kMinimumSpliceBytes = 16 << 10;
constexpr std::size_t kSpliceRequestBytes = kStreamingPipeBytes;
constexpr std::size_t kSpliceRoundsPerEvent = 16;
constexpr unsigned int kSpliceFlags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
constexpr std::size_t kEventBatch = 64;
constexpr std::size_t kAcceptBatch = 32;
constexpr auto kPollInterval = std::chrono::milliseconds(250);
constexpr auto kPipeSweepInterval = std::chrono::seconds(1);
constexpr auto kMemoryPollInterval = std::chrono::milliseconds(25);
constexpr auto kMemoryCheckInterval = std::chrono::milliseconds(5);
constexpr std::size_t kShedDivisor = 8;
constexpr auto kOrphanTimeout = std::chrono::milliseconds(60'000);
constexpr std::uint64_t kListenerToken = 0;
constexpr std::uint64_t kInboxToken = 1;
constexpr unsigned int kSideBits = 1;
constexpr std::uint64_t kSideMask = (std::uint64_t{1} << kSideBits) - 1;
constexpr std::uint32_t kReadEvents = EPOLLIN | EPOLLRDHUP;
constexpr std::uint32_t kReadReady = kReadEvents | EPOLLHUP;
constexpr std::uint32_t kWriteReady = EPOLLOUT | EPOLLHUP;

enum class Phase : std::uint8_t { Header, Connecting, Forwarding };
constexpr std::size_t kPhaseCount = 3;
static_assert(static_cast<std::size_t>(Phase::Forwarding) + 1 == kPhaseCount);

enum class Side : std::uint8_t { Client, Backend };

enum class Result {
    Keep,
    Done,
    ClientClosed,
    InvalidHeader,
    BackendFailed,
    ResourceLimit,
    OverShare,
};

enum class PumpStatus { Ok, SourceFailed, DestinationFailed, CopyInstead };

struct Readiness {
    bool source_readable = false;
    bool destination_writable = false;
};

constexpr Readiness kFullyReady{.source_readable = true, .destination_writable = true};

std::uint64_t event_token(ConnectionId id, Side side) {
    return (id << kSideBits) | static_cast<std::uint64_t>(side);
}

ConnectionId token_connection(std::uint64_t token) {
    return token >> kSideBits;
}

Side token_side(std::uint64_t token) {
    return static_cast<Side>(token & kSideMask);
}

Side opposite(Side side) {
    return side == Side::Client ? Side::Backend : Side::Client;
}

Readiness event_readiness(Side source, Side event_side, std::uint32_t events) {
    return {.source_readable = event_side == source && (events & kReadReady) != 0,
            .destination_writable = event_side != source && (events & kWriteReady) != 0};
}

struct Pipe {
    FileDescriptor read_end;
    FileDescriptor write_end;
    bool grown = false;          // holds one of the worker's streaming pipe slots
    bool growth_refused = false; // the per-user budget is spent, so stop asking for this pipe
};

class PipePool {
public:
    explicit PipePool(std::size_t streaming_limit) : streaming_limit_(streaming_limit) {}

    [[nodiscard]] std::optional<Pipe> acquire() {
        if (!idle_.empty()) {
            auto pipe = std::move(idle_.back());
            idle_.pop_back();
            return pipe;
        }
        std::array<int, 2> ends{};
        if (::pipe2(ends.data(), O_NONBLOCK | O_CLOEXEC) != 0)
            return std::nullopt;
        return Pipe{.read_end = FileDescriptor(ends[0]), .write_end = FileDescriptor(ends[1])};
    }

    void grow(Pipe& pipe) {
        if (pipe.grown || pipe.growth_refused || grown_ == streaming_limit_)
            return;
        const auto size = static_cast<int>(kStreamingPipeBytes);
        if (::fcntl(pipe.write_end.get(), F_SETPIPE_SZ, size) < 0) {
            pipe.growth_refused = true;
            return;
        }
        pipe.grown = true;
        ++grown_;
    }

    void release(std::optional<Pipe>& pipe) {
        if (pipe && !pipe->grown && !pipe->growth_refused && idle_.size() < kCachedPipesPerWorker)
            idle_.push_back(std::move(*pipe));
        discard(pipe);
    }

    void discard(std::optional<Pipe>& pipe) {
        if (pipe && pipe->grown)
            --grown_;
        pipe.reset();
    }

private:
    std::vector<Pipe> idle_;
    std::size_t streaming_limit_;
    std::size_t grown_ = 0;
};

struct Direction {
    std::vector<std::uint8_t> staged;
    std::size_t staged_sent = 0;
    std::optional<Pipe> pipe;
    std::size_t piped_bytes = 0;
    bool use_splice = false;
    bool spliced_recently = false;
    bool eof = false;

    [[nodiscard]] bool has_staged() const { return staged_sent != staged.size(); }
    [[nodiscard]] bool pending() const { return has_staged() || piped_bytes != 0; }
    [[nodiscard]] bool can_read() const { return !pending() && !eof; }

    void release_staged_if_sent() {
        if (has_staged())
            return;
        std::vector<std::uint8_t>().swap(staged);
        staged_sent = 0;
    }
};

struct Connection {
    FileDescriptor client;
    FileDescriptor backend;
    Endpoint relay;
    std::vector<std::uint8_t> header;
    std::size_t header_received = 0;
    Direction to_backend;
    Direction to_client;
    Phase phase = Phase::Header;
    Clock::time_point expires_at{};
    std::optional<DeadlineQueue::iterator> deadline_position;
    std::optional<IpAddress> counted_client;
    std::uint32_t client_events = 0;
    std::uint32_t backend_events = 0;
    bool in_pipe_sweep = false;

    [[nodiscard]] Direction& direction_from(Side side) {
        return side == Side::Client ? to_backend : to_client;
    }

    [[nodiscard]] bool holds_pipe() const {
        return to_backend.pipe.has_value() || to_client.pipe.has_value();
    }

    [[nodiscard]] int socket(Side side) const {
        return side == Side::Client ? client.get() : backend.get();
    }
};

void grow_header_buffer(std::vector<std::uint8_t>& header, std::size_t limit) {
    const auto grown = std::min(header.size() * 2, limit);
    header.reserve(grown);
    header.resize(grown);
}

void stage_payload_after_header(Connection& connection, std::size_t header_size) {
    auto& header = connection.header;
    header.resize(connection.header_received);
    connection.to_backend.staged = std::exchange(header, {});
    connection.to_backend.staged_sent = header_size;
    connection.to_backend.release_staged_if_sent();
    connection.header_received = 0;
}

std::size_t socket_queued_bytes(const FileDescriptor& socket) {
    if (!socket)
        return 0;
    int unread = 0;
    int unsent = 0;
    if (::ioctl(socket.get(), FIONREAD, &unread) != 0 || unread < 0)
        unread = 0;
    if (::ioctl(socket.get(), TIOCOUTQ, &unsent) != 0 || unsent < 0)
        unsent = 0;
    return static_cast<std::size_t>(unread) + static_cast<std::size_t>(unsent);
}

std::size_t direction_held_bytes(const Direction& direction) {
    return direction.staged.capacity() + direction.piped_bytes;
}

std::size_t held_bytes(const Connection& connection) {
    return socket_queued_bytes(connection.client) + socket_queued_bytes(connection.backend) +
           direction_held_bytes(connection.to_backend) +
           direction_held_bytes(connection.to_client) + connection.header.capacity();
}

bool is_bound_to(const FileDescriptor& socket, const Endpoint& endpoint) {
    sockaddr_storage local{};
    socklen_t length = sizeof(local);
    if (::getsockname(socket.get(), reinterpret_cast<sockaddr*>(&local), &length) != 0)
        return false;
    const auto bound = from_socket_address(local);
    return bound && bound->address == endpoint.address && bound->port == endpoint.port;
}

void reset_on_close(const FileDescriptor& socket) {
    if (!socket)
        return;
    const linger reset{.l_onoff = 1, .l_linger = 0};
    static_cast<void>(::setsockopt(socket.get(), SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)));
}

std::chrono::milliseconds orphan_timeout(const Config& config) {
    if (config.user_timeout.count() == 0)
        return kOrphanTimeout;
    return std::min(config.user_timeout, kOrphanTimeout);
}

void limit_orphan_lifetime(const FileDescriptor& socket, bool memory_pressure,
                           std::chrono::milliseconds max_lifetime) {
    int unsent = 0;
    if (!socket || ::ioctl(socket.get(), TIOCOUTQ, &unsent) != 0 || unsent <= 0)
        return;
    if (memory_pressure) {
        reset_on_close(socket);
        return;
    }
    const auto timeout = static_cast<unsigned int>(max_lifetime.count());
    static_cast<void>(
        ::setsockopt(socket.get(), IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, sizeof(timeout)));
}

[[nodiscard]] bool update_events(int epoll, int descriptor, std::uint64_t token,
                                 std::uint32_t& current, std::uint32_t wanted) {
    if (current == wanted)
        return true;
    int operation = EPOLL_CTL_MOD;
    if (wanted == 0)
        operation = EPOLL_CTL_DEL;
    else if (current == 0)
        operation = EPOLL_CTL_ADD;
    epoll_event event{.events = wanted, .data = {.u64 = token}};
    if (::epoll_ctl(epoll, operation, descriptor, &event) != 0)
        return false;
    current = wanted;
    return true;
}

std::uint32_t forwarding_events(const Direction& outgoing, const Direction& incoming) {
    std::uint32_t events = 0;
    if (outgoing.can_read())
        events |= kReadEvents;
    if (incoming.pending())
        events |= EPOLLOUT;
    return events;
}

PumpStatus finish_direction(Direction& direction, int destination) {
    direction.eof = true;
    if (::shutdown(destination, SHUT_WR) == 0 || errno == ENOTCONN)
        return PumpStatus::Ok;
    return PumpStatus::DestinationFailed;
}

PumpStatus send_staged(Direction& direction, int destination, bool& moved) {
    const auto unsent = std::span(direction.staged).subspan(direction.staged_sent);
    const auto sent = ::send(destination, unsent.data(), unsent.size(), MSG_NOSIGNAL);
    if (sent <= 0)
        return sent < 0 && is_retryable(errno) ? PumpStatus::Ok : PumpStatus::DestinationFailed;
    direction.staged_sent += static_cast<std::size_t>(sent);
    moved = true;
    direction.release_staged_if_sent();
    return PumpStatus::Ok;
}

PumpStatus drain_pipe(Direction& direction, int destination, PipePool& pipes, bool& moved) {
    if (!direction.pipe)
        return PumpStatus::DestinationFailed;
    const auto sent = ::splice(direction.pipe->read_end.get(), nullptr, destination, nullptr,
                               direction.piped_bytes, kSpliceFlags);
    if (sent <= 0)
        return sent < 0 && is_retryable(errno) ? PumpStatus::Ok : PumpStatus::DestinationFailed;
    direction.piped_bytes -= static_cast<std::size_t>(sent);
    moved = true;
    if (direction.piped_bytes == 0 && !direction.use_splice)
        pipes.release(direction.pipe);
    return PumpStatus::Ok;
}

PumpStatus splice_through(Direction& direction, int source, int destination, PipePool& pipes,
                          bool& moved) {
    for (std::size_t round = 0; round < kSpliceRoundsPerEvent; ++round) {
        if (!direction.pipe)
            direction.pipe = pipes.acquire();
        if (!direction.pipe)
            return PumpStatus::CopyInstead;
        pipes.grow(*direction.pipe);
        const auto received = ::splice(source, nullptr, direction.pipe->write_end.get(), nullptr,
                                       kSpliceRequestBytes, kSpliceFlags);
        if (received < 0) {
            if (!is_retryable(errno))
                return PumpStatus::SourceFailed;
            return round == 0 ? PumpStatus::CopyInstead : PumpStatus::Ok;
        }
        if (received == 0)
            return PumpStatus::CopyInstead;
        direction.piped_bytes = static_cast<std::size_t>(received);
        direction.spliced_recently = true;
        direction.use_splice = direction.piped_bytes >= kMinimumSpliceBytes;
        const auto status = drain_pipe(direction, destination, pipes, moved);
        if (status != PumpStatus::Ok || direction.piped_bytes != 0 || !direction.use_splice)
            return status;
    }
    return PumpStatus::Ok;
}

PumpStatus copy_through(Direction& direction, int source, int destination,
                        std::span<std::uint8_t> scratch, bool& moved) {
    const auto received = ::recv(source, scratch.data(), scratch.size(), 0);
    if (received < 0)
        return is_retryable(errno) ? PumpStatus::Ok : PumpStatus::SourceFailed;
    if (received == 0)
        return finish_direction(direction, destination);
    const auto chunk = scratch.first(static_cast<std::size_t>(received));
    const auto sent = ::send(destination, chunk.data(), chunk.size(), MSG_NOSIGNAL);
    if (sent < 0 && !is_retryable(errno))
        return PumpStatus::DestinationFailed;
    const auto delivered = sent > 0 ? static_cast<std::size_t>(sent) : std::size_t{0};
    if (delivered > 0)
        moved = true;
    if (delivered < chunk.size()) {
        const auto unsent = chunk.subspan(delivered);
        direction.staged.assign(unsent.begin(), unsent.end());
    }
    direction.use_splice = chunk.size() == scratch.size();
    return PumpStatus::Ok;
}

PumpStatus pump(Direction& direction, int source, int destination, Readiness ready,
                PipePool& pipes, std::span<std::uint8_t> scratch, bool& moved) {
    if (direction.has_staged()) {
        if (!ready.destination_writable)
            return PumpStatus::Ok;
        const auto status = send_staged(direction, destination, moved);
        if (status != PumpStatus::Ok || direction.has_staged())
            return status;
    }
    if (direction.piped_bytes != 0) {
        if (!ready.destination_writable)
            return PumpStatus::Ok;
        return drain_pipe(direction, destination, pipes, moved);
    }
    if (direction.eof || !ready.source_readable)
        return PumpStatus::Ok;
    if (direction.use_splice) {
        const auto status = splice_through(direction, source, destination, pipes, moved);
        if (status != PumpStatus::CopyInstead)
            return status;
        pipes.release(direction.pipe);
        direction.use_splice = false;
    }
    return copy_through(direction, source, destination, scratch, moved);
}

class TcpWorker {
public:
    TcpWorker(const Config& config, FileDescriptor listener, std::size_t connection_limit,
              Metrics& metrics, const TcpShared& shared, std::size_t worker_index)
        : config_(config), metrics_(metrics), balancer_(shared.balancer),
          fair_share_(shared.fair_share), memory_guard_(shared.memory_guard),
          worker_index_(worker_index), listener_(std::move(listener)),
          connection_limit_(connection_limit), epoll_(::epoll_create1(EPOLL_CLOEXEC)),
          pipes_(worker_share(config.streaming_pipe_budget, config.workers, worker_index)) {
        if (!epoll_)
            throw_system_error("create TCP epoll");
        if (!watch_listener(EPOLLIN))
            throw_system_error("watch the TCP listener");
        std::uint32_t inbox_events = 0;
        if (!update_events(epoll_.get(), balancer_.inbox_descriptor(worker_index_), kInboxToken,
                           inbox_events, EPOLLIN))
            throw_system_error("watch the worker inbox");
    }

    TcpWorker(const TcpWorker&) = delete;
    TcpWorker& operator=(const TcpWorker&) = delete;

    void run(const std::stop_token& stop) {
        std::array<epoll_event, kEventBatch> events{};
        while (!stop.stop_requested()) {
            const int count = ::epoll_wait(epoll_.get(), events.data(),
                                           static_cast<int>(events.size()), poll_timeout());
            if (count < 0) {
                if (errno == EINTR)
                    continue;
                throw_system_error("wait for TCP events");
            }
            const auto now = Clock::now();
            expire(now);
            sweep_pipes(now);
            guard_memory(now);
            if (listener_events_ == 0 && now >= resume_accept_at_)
                resume_accepting(now);
            for (int index = 0; index < count; ++index) {
                handle_event(events[static_cast<std::size_t>(index)], now);
                if (memory_guard_.enabled())
                    guard_memory(Clock::now());
            }
        }
    }

private:
    using Connections = std::unordered_map<ConnectionId, Connection>;

    int poll_timeout() const {
        const auto now = Clock::now();
        auto wake_at = now + kPollInterval;
        if (memory_pressure_)
            wake_at = now + kMemoryCheckInterval;
        else if (memory_guard_.enabled())
            wake_at = now + kMemoryPollInterval;
        if (listener_events_ == 0)
            wake_at = std::min(wake_at, resume_accept_at_);
        for (const auto& queue : deadlines_) {
            if (!queue.empty())
                wake_at = std::min(wake_at, connections_.find(queue.front())->second.expires_at);
        }
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(wake_at - now);
        return static_cast<int>(std::max(remaining, std::chrono::milliseconds::zero()).count());
    }

    [[nodiscard]] bool watch_listener(std::uint32_t wanted) {
        return update_events(epoll_.get(), listener_.get(), kListenerToken, listener_events_,
                             wanted);
    }

    void pause_accepting(Clock::time_point now) {
        resume_accept_at_ = now + kPollInterval;
        static_cast<void>(watch_listener(0));
    }

    void resume_accepting(Clock::time_point now) {
        if (!watch_listener(EPOLLIN))
            resume_accept_at_ = now + kPollInterval;
    }

    void enter_phase(ConnectionId id, Connection& connection, Phase phase, Clock::time_point now,
                     std::chrono::milliseconds timeout) {
        auto& old_queue = deadlines_[static_cast<std::size_t>(connection.phase)];
        auto& new_queue = deadlines_[static_cast<std::size_t>(phase)];
        connection.phase = phase;
        if (timeout.count() == 0) {
            if (connection.deadline_position) {
                old_queue.erase(*connection.deadline_position);
                connection.deadline_position.reset();
            }
            return;
        }
        connection.expires_at = now + timeout;
        if (connection.deadline_position)
            new_queue.splice(new_queue.end(), old_queue, *connection.deadline_position);
        else
            connection.deadline_position = new_queue.insert(new_queue.end(), id);
    }

    void remove(Connections::iterator entry) {
        auto& connection = entry->second;
        if (connection.deadline_position) {
            auto& queue = deadlines_[static_cast<std::size_t>(connection.phase)];
            queue.erase(*connection.deadline_position);
        }
        pipes_.discard(connection.to_backend.pipe);
        pipes_.discard(connection.to_client.pipe);
        if (connection.counted_client)
            fair_share_.release(*connection.counted_client);
        limit_orphan_lifetime(connection.client, memory_pressure_, orphan_timeout(config_));
        limit_orphan_lifetime(connection.backend, memory_pressure_, kOrphanTimeout);
        connections_.erase(entry);
        balancer_.closed(worker_index_);
    }

    void remove_with_reset(Connections::iterator entry) {
        reset_on_close(entry->second.client);
        reset_on_close(entry->second.backend);
        remove(entry);
    }

    void count_expiry(Phase phase) {
        switch (phase) {
        case Phase::Header:
            increment(metrics_.header_timeouts);
            return;
        case Phase::Connecting:
            metrics_.count_backend_failure(BackendFailure::ConnectTimeout);
            return;
        case Phase::Forwarding:
            return;
        }
    }

    void expire(Clock::time_point now) {
        for (auto& queue : deadlines_) {
            while (!queue.empty()) {
                const auto entry = connections_.find(queue.front());
                if (entry->second.expires_at > now)
                    break;
                count_expiry(entry->second.phase);
                if (held_bytes(entry->second) != 0)
                    remove_with_reset(entry);
                else
                    remove(entry);
            }
        }
    }

    void sweep_pipes(Clock::time_point now) {
        if (now < next_pipe_sweep_)
            return;
        next_pipe_sweep_ = now + kPipeSweepInterval;
        std::erase_if(pipe_holders_, [this](ConnectionId id) {
            const auto entry = connections_.find(id);
            if (entry == connections_.end())
                return true;
            auto& connection = entry->second;
            release_idle_pipe(connection.to_backend);
            release_idle_pipe(connection.to_client);
            connection.in_pipe_sweep = connection.holds_pipe();
            return !connection.in_pipe_sweep;
        });
    }

    void join_pipe_sweep(ConnectionId id, Connection& connection) {
        if (connection.in_pipe_sweep || !connection.holds_pipe())
            return;
        connection.in_pipe_sweep = true;
        pipe_holders_.push_back(id);
    }

    void release_idle_pipe(Direction& direction) {
        if (direction.pipe && direction.piped_bytes == 0 && !direction.spliced_recently) {
            pipes_.release(direction.pipe);
            direction.use_splice = false;
        }
        direction.spliced_recently = false;
    }

    void guard_memory(Clock::time_point now) {
        if (!memory_guard_.enabled() || now < next_memory_check_)
            return;
        next_memory_check_ = now + kMemoryCheckInterval;
        memory_pressure_ = memory_guard_.under_pressure();
        if (!memory_pressure_)
            return;
        pause_accepting(now);
        shed_largest_connections();
        const auto finished = Clock::now();
        next_memory_check_ = finished + std::max<Clock::duration>(kMemoryCheckInterval,
                                                                  (finished - now) * 2);
    }

    void shed_largest_connections() {
        std::vector<std::pair<std::size_t, ConnectionId>> holders;
        for (const auto& [id, connection] : connections_) {
            if (const auto bytes = held_bytes(connection); bytes != 0)
                holders.emplace_back(bytes, id);
        }
        if (holders.empty())
            return;
        const auto count = std::max<std::size_t>(1, holders.size() / kShedDivisor);
        const auto largest = holders.begin() + static_cast<std::ptrdiff_t>(count);
        std::ranges::partial_sort(holders, largest, std::ranges::greater{});
        for (const auto& holder : std::ranges::subrange(holders.begin(), largest)) {
            increment(metrics_.memory_shed);
            remove_with_reset(connections_.find(holder.second));
        }
    }

    void accept_clients(Clock::time_point now) {
        for (std::size_t attempt = 0; attempt < kAcceptBatch; ++attempt) {
            sockaddr_storage relay_address{};
            socklen_t length = sizeof(relay_address);
            FileDescriptor client(::accept4(listener_.get(),
                                            reinterpret_cast<sockaddr*>(&relay_address), &length,
                                            SOCK_NONBLOCK | SOCK_CLOEXEC));
            if (!client) {
                if (errno == EINTR || errno == ECONNABORTED || errno == EPROTO)
                    continue;
                if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) {
                    pause_accepting(now);
                    increment(metrics_.limit_reached);
                }
                return;
            }

            const auto relay = from_socket_address(relay_address);
            if (!relay || !config_.trusted.contains(relay->address)) {
                increment(metrics_.untrusted);
                continue;
            }
            const auto owner = balancer_.choose(worker_index_);
            if (owner != worker_index_) {
                balancer_.hand_off(owner, Handoff{.client = std::move(client), .relay = *relay});
                continue;
            }
            balancer_.opened(worker_index_);
            adopt(std::move(client), *relay, now);
        }
    }

    void adopt(FileDescriptor client, const Endpoint& relay, Clock::time_point now) {
        if (connections_.size() >= connection_limit_) {
            increment(metrics_.limit_reached);
            balancer_.closed(worker_index_);
            return;
        }
        const auto id = next_id_++;
        const auto entry = connections_.try_emplace(id).first;
        auto& connection = entry->second;
        connection.client = std::move(client);
        connection.relay = relay;
        enter_phase(id, connection, Phase::Header, now, config_.header_timeout);
        if (!watch(id, connection)) {
            increment(metrics_.limit_reached);
            remove(entry);
        }
    }

    void adopt_handoffs(Clock::time_point now) {
        for (auto& handoff : balancer_.take_handoffs(worker_index_))
            adopt(std::move(handoff.client), handoff.relay, now);
    }

    [[nodiscard]] bool watch(ConnectionId id, Connection& connection) {
        std::uint32_t client_events = 0;
        std::uint32_t backend_events = 0;
        switch (connection.phase) {
        case Phase::Header:
            client_events = kReadEvents;
            break;
        case Phase::Connecting:
            backend_events = EPOLLOUT;
            break;
        case Phase::Forwarding:
            client_events = forwarding_events(connection.to_backend, connection.to_client);
            backend_events = forwarding_events(connection.to_client, connection.to_backend);
            break;
        }
        return update_events(epoll_.get(), connection.client.get(), event_token(id, Side::Client),
                             connection.client_events, client_events) &&
               update_events(epoll_.get(), connection.backend.get(),
                             event_token(id, Side::Backend), connection.backend_events,
                             backend_events);
    }

    Result backend_failed(BackendFailure failure) {
        metrics_.count_backend_failure(failure);
        return Result::BackendFailed;
    }

    Result side_failed(Side side) {
        if (side == Side::Backend)
            return backend_failed(BackendFailure::Forwarding);
        return Result::ClientClosed;
    }

    Result pump_failed(PumpStatus status, Side source) {
        return side_failed(status == PumpStatus::SourceFailed ? source : opposite(source));
    }

    PumpStatus pump_from(Connection& connection, Side source, Readiness ready, bool& moved) {
        return pump(connection.direction_from(source), connection.socket(source),
                    connection.socket(opposite(source)), ready, pipes_, scratch_, moved);
    }

    void salvage(Connection& connection, Side failed) {
        bool moved = false;
        static_cast<void>(pump_from(connection, failed, kFullyReady, moved));
    }

    Result begin_forwarding(ConnectionId id, Connection& connection, Clock::time_point now) {
        enter_phase(id, connection, Phase::Forwarding, now, config_.idle_timeout);
        if (!connection.to_backend.has_staged())
            return Result::Keep;
        bool moved = false;
        if (send_staged(connection.to_backend, connection.backend.get(), moved) != PumpStatus::Ok)
            return backend_failed(BackendFailure::Forwarding);
        return Result::Keep;
    }

    Result connect_backend(ConnectionId id, Connection& connection, const ProxyHeader& header,
                           Clock::time_point now) {
        const int family = header.source ? header.source->address.family :
                                           connection.relay.address.family;
        const auto& endpoint = backend_for(config_, family);
        if (!endpoint)
            return backend_failed(BackendFailure::NoBackend);
        auto backend = open_backend_socket(config_, *endpoint, header.source, SOCK_STREAM);
        if (!backend)
            return backend_failed(backend.error());
        connection.backend = std::move(*backend);
        const auto address = to_socket_address(*endpoint);
        const bool connected =
            ::connect(connection.backend.get(), address.data(), address.length) == 0;
        if (!connected && errno != EINPROGRESS)
            return backend_failed(BackendFailure::Connect);
        if (header.source && !is_bound_to(connection.backend, *header.source))
            return backend_failed(BackendFailure::Bind);
        if (connected)
            return begin_forwarding(id, connection, now);
        enter_phase(id, connection, Phase::Connecting, now, config_.connect_timeout);
        return Result::Keep;
    }

    Result read_header(ConnectionId id, Connection& connection, Clock::time_point now) {
        auto& header = connection.header;
        const auto limit = config_.max_header_bytes;
        if (header.empty())
            header.resize(std::min(kInitialHeaderBytes, limit));
        const auto received = ::recv(connection.client.get(),
                                     header.data() + connection.header_received,
                                     header.size() - connection.header_received, 0);
        if (received < 0 && is_retryable(errno))
            return Result::Keep;
        if (received <= 0)
            return connection.header_received == 0 ? Result::ClientClosed : Result::InvalidHeader;

        connection.header_received += static_cast<std::size_t>(received);
        const auto parsed = parse_proxy_header(
            std::span(header).first(connection.header_received), ProxyTransport::Stream);
        if (!parsed) {
            if (parsed.error() != ProxyError::NeedMore || connection.header_received >= limit)
                return Result::InvalidHeader;
            if (connection.header_received == header.size())
                grow_header_buffer(header, limit);
            return Result::Keep;
        }

        const auto& claimed = parsed->source;
        if (!relay_may_claim(connection.relay, claimed))
            return Result::InvalidHeader;
        const auto client = claimed ? claimed->address : connection.relay.address;
        if (!fair_share_.admit(client))
            return Result::OverShare;
        connection.counted_client = client;
        stage_payload_after_header(connection, parsed->size);
        return connect_backend(id, connection, *parsed, now);
    }

    Result finish_connect(ConnectionId id, Connection& connection, Side side,
                          Clock::time_point now) {
        if (side == Side::Client)
            return Result::Keep;
        int error = 0;
        socklen_t length = sizeof(error);
        if (::getsockopt(connection.backend.get(), SOL_SOCKET, SO_ERROR, &error, &length) != 0 ||
            error != 0)
            return backend_failed(BackendFailure::Connect);
        return begin_forwarding(id, connection, now);
    }

    Result forward(ConnectionId id, Connection& connection, Side side, std::uint32_t events,
                   Clock::time_point now) {
        if ((events & EPOLLERR) != 0) {
            salvage(connection, side);
            return side_failed(side);
        }
        bool moved = false;
        const auto upload_ready = event_readiness(Side::Client, side, events);
        const auto upload = pump_from(connection, Side::Client, upload_ready, moved);
        if (upload != PumpStatus::Ok)
            return pump_failed(upload, Side::Client);
        const auto download_ready = event_readiness(Side::Backend, side, events);
        const auto download = pump_from(connection, Side::Backend, download_ready, moved);
        if (download != PumpStatus::Ok)
            return pump_failed(download, Side::Backend);

        join_pipe_sweep(id, connection);
        if (connection.to_backend.eof && connection.to_client.eof)
            return Result::Done;
        if (moved)
            enter_phase(id, connection, Phase::Forwarding, now, config_.idle_timeout);
        return Result::Keep;
    }

    Result process(ConnectionId id, Connection& connection, Side side, std::uint32_t events,
                   Clock::time_point now) {
        switch (connection.phase) {
        case Phase::Header:
            return read_header(id, connection, now);
        case Phase::Connecting:
            return finish_connect(id, connection, side, now);
        case Phase::Forwarding:
            return forward(id, connection, side, events, now);
        }
        std::unreachable();
    }

    void count_close(Result result) {
        switch (result) {
        case Result::InvalidHeader:
            increment(metrics_.invalid_header);
            return;
        case Result::ResourceLimit:
            increment(metrics_.limit_reached);
            return;
        case Result::OverShare:
            increment(metrics_.share_refused);
            return;
        case Result::Keep:
        case Result::Done:
        case Result::ClientClosed:
        case Result::BackendFailed:
            return;
        }
    }

    void handle_event(const epoll_event& event, Clock::time_point now) {
        const std::uint64_t token = event.data.u64;
        if (token == kListenerToken) {
            if ((event.events & EPOLLERR) != 0)
                throw SystemError("TCP listener reported an error");
            accept_clients(now);
            return;
        }
        if (token == kInboxToken) {
            adopt_handoffs(now);
            return;
        }
        const auto entry = connections_.find(token_connection(token));
        if (entry == connections_.end())
            return;
        auto& connection = entry->second;
        auto result = process(entry->first, connection, token_side(token), event.events, now);
        if (result == Result::Keep) {
            if (watch(entry->first, connection))
                return;
            result = Result::ResourceLimit;
        }
        count_close(result);
        remove(entry);
    }

    const Config& config_;
    Metrics& metrics_;
    Balancer& balancer_;
    FairShare& fair_share_;
    const MemoryGuard& memory_guard_;
    std::size_t worker_index_;
    FileDescriptor listener_;
    std::size_t connection_limit_;
    FileDescriptor epoll_;
    PipePool pipes_;
    std::vector<std::uint8_t> scratch_ = std::vector<std::uint8_t>(kScratchBytes);
    Connections connections_;
    std::vector<ConnectionId> pipe_holders_;
    std::array<DeadlineQueue, kPhaseCount> deadlines_;
    ConnectionId next_id_ = 1;
    std::uint32_t listener_events_ = 0;
    Clock::time_point resume_accept_at_{};
    Clock::time_point next_memory_check_{};
    Clock::time_point next_pipe_sweep_{};
    bool memory_pressure_ = false;
};

} // namespace

void run_tcp(const std::stop_token& stop, const Config& config, FileDescriptor listener,
             std::size_t connection_limit, Metrics& metrics, const TcpShared& shared,
             std::size_t worker_index) {
    TcpWorker worker(config, std::move(listener), connection_limit, metrics, shared, worker_index);
    worker.run(stop);
}

} // namespace erikslund::mmproxy
