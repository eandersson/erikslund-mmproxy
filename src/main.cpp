#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "mmproxy/config.hpp"
#include "mmproxy/memory_guard.hpp"
#include "mmproxy/metrics.hpp"
#include "mmproxy/socket.hpp"
#include "mmproxy/tcp.hpp"
#include "mmproxy/udp.hpp"

namespace erikslund::mmproxy {
namespace {

FileDescriptor termination_signals() {
    sigset_t signals;
    ::sigemptyset(&signals);
    ::sigaddset(&signals, SIGINT);
    ::sigaddset(&signals, SIGTERM);
    if (::sigprocmask(SIG_BLOCK, &signals, nullptr) != 0)
        throw_socket_error("block termination signals");
    FileDescriptor receiver(::signalfd(-1, &signals, SFD_CLOEXEC));
    if (!receiver)
        throw_socket_error("open termination signal descriptor");
    return receiver;
}

void ignore_broken_pipes() {
    struct sigaction ignore{};
    ignore.sa_handler = SIG_IGN;
    ::sigemptyset(&ignore.sa_mask);
    if (::sigaction(SIGPIPE, &ignore, nullptr) != 0)
        throw_socket_error("ignore SIGPIPE");
}

void raise_open_file_limit() {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur >= limit.rlim_max)
        return;
    limit.rlim_cur = limit.rlim_max;
    static_cast<void>(::setrlimit(RLIMIT_NOFILE, &limit));
}

constexpr int kReportIntervalMs = 60'000;

struct Problems {
    std::uint64_t untrusted = 0;
    std::uint64_t invalid_header = 0;
    std::uint64_t header_timeouts = 0;
    std::uint64_t limit_reached = 0;
    std::uint64_t memory_shed = 0;
    std::uint64_t share_refused = 0;
    std::uint64_t flows_evicted = 0;
    std::uint64_t udp_dropped = 0;
    std::array<std::uint64_t, kUpstreamFailureCount> upstream_errors{};
};

Problems count_problems(const std::vector<Metrics>& metrics) {
    constexpr auto kRelaxed = std::memory_order_relaxed;
    Problems total;
    for (const auto& shard : metrics) {
        total.untrusted += shard.untrusted.load(kRelaxed);
        total.invalid_header += shard.invalid_header.load(kRelaxed);
        total.header_timeouts +=
            shard.timeouts[static_cast<std::size_t>(TimeoutPhase::Header)].load(kRelaxed);
        total.limit_reached += shard.limit_reached.load(kRelaxed);
        total.memory_shed += shard.memory_shed.load(kRelaxed);
        total.share_refused += shard.share_refused.load(kRelaxed);
        total.flows_evicted += shard.flows_evicted.load(kRelaxed);
        total.udp_dropped += shard.udp_dropped.load(kRelaxed);
        for (std::size_t reason = 0; reason < kUpstreamFailureCount; ++reason)
            total.upstream_errors[reason] += shard.upstream_errors[reason].load(kRelaxed);
    }
    return total;
}

std::string describe_changes(const Problems& current, const Problems& before) {
    std::string text;
    const auto add = [&text](std::uint64_t delta, std::string_view what) {
        if (delta != 0)
            text += std::format("{}{} {}", text.empty() ? "" : ", ", delta, what);
    };
    add(current.untrusted - before.untrusted, "untrusted peers");
    add(current.invalid_header - before.invalid_header, "invalid headers");
    add(current.header_timeouts - before.header_timeouts, "header timeouts");
    add(current.limit_reached - before.limit_reached, "refused at a limit");
    add(current.memory_shed - before.memory_shed, "closed under memory pressure");
    add(current.share_refused - before.share_refused, "refused over a client's share");
    add(current.flows_evicted - before.flows_evicted, "UDP flows evicted");
    add(current.udp_dropped - before.udp_dropped, "UDP datagrams dropped");
    // In UpstreamFailure order.
    constexpr std::array<std::string_view, kUpstreamFailureCount> kUpstreamFailures{
        "clients without a backend for their family", "backend socket setup failures",
        "claimed-address bind failures", "backend connect failures", "backend connect timeouts",
        "backend failures mid-relay"};
    for (std::size_t reason = 0; reason < kUpstreamFailureCount; ++reason)
        add(current.upstream_errors[reason] - before.upstream_errors[reason],
            kUpstreamFailures[reason]);
    return text;
}

template <typename Function>
void guard_worker(const FileDescriptor& failure, Function run) noexcept {
    try {
        run();
        return;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "mmproxy worker error: %s\n", error.what());
    } catch (...) {
        std::fputs("mmproxy worker failed\n", stderr);
    }
    constexpr std::uint64_t kFailure = 1;
    ssize_t written;
    do {
        written = ::write(failure.get(), &kFailure, sizeof(kFailure));
    } while (written < 0 && errno == EINTR);
}

int supervise(const Config& config) {
    if (config.workers == 0)
        throw ConfigError("at least one worker is required");
    ignore_broken_pipes();
    const auto signals = termination_signals();
    const FileDescriptor failure(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (!failure)
        throw_socket_error("open worker failure descriptor");
    check_upstream_permissions(config);

    const int socket_type = config.transport == Transport::Tcp ? SOCK_STREAM : SOCK_DGRAM;
    std::vector<FileDescriptor> listeners;
    listeners.reserve(config.workers);
    for (std::size_t index = 0; index < config.workers; ++index)
        listeners.push_back(make_listener(config, socket_type));

    std::vector<Metrics> metrics(config.workers);
    Balancer balancer(config.workers);
    FairShare fair_share(config.max_connections);
    const auto memory_limit =
        config.transport == Transport::Tcp ? find_memory_limit() : std::nullopt;
    const auto memory = memory_limit ? MemoryGuard(*memory_limit) : MemoryGuard();
    const TcpShared tcp_shared{.balancer = balancer, .fair_share = fair_share, .memory = memory};
    std::vector<std::jthread> threads;
    threads.reserve(config.workers);
    const auto slots_per_worker = config.max_connections / config.workers;
    const auto extra_slots = config.max_connections % config.workers;
    for (std::size_t index = 0; index < config.workers; ++index) {
        const auto limit = slots_per_worker + (index < extra_slots ? 1U : 0U);
        auto worker = [&, index, limit, listener = std::move(listeners[index])]
                      (std::stop_token stop) mutable {
            guard_worker(failure, [&] {
                if (config.transport == Transport::Tcp)
                    run_tcp(stop, config, std::move(listener), limit, metrics[index], tcp_shared,
                            index);
                else
                    run_udp(stop, config, std::move(listener), limit, metrics[index]);
            });
        };
        threads.emplace_back(std::move(worker));
    }

    const auto startup = std::format("mmproxy {} ready ({} workers, {} connections or flows)\n",
                                     MMPROXY_VERSION, config.workers, config.max_connections);
    std::fputs(startup.c_str(), stderr);
    if (memory.enabled()) {
        constexpr std::uint64_t kBytesPerMebibyte = 1 << 20;
        const auto guard = std::format(
            "mmproxy closes the connections holding the most bytes above {} MiB of memory use\n",
            memory.threshold_bytes() / kBytesPerMebibyte);
        std::fputs(guard.c_str(), stderr);
        if (memory_limit && memory_limit->shared)
            std::fputs("mmproxy: the memory limit belongs to a parent cgroup, so other processes' "
                       "memory can also trigger shedding\n",
                       stderr);
    }
    pollfd descriptors[] = {{signals.get(), POLLIN, 0}, {failure.get(), POLLIN, 0}};
    auto reported = count_problems(metrics);
    int ready;
    for (;;) {
        ready = ::poll(descriptors, std::size(descriptors), kReportIntervalMs);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready != 0)
            break;
        const auto current = count_problems(metrics);
        if (const auto changes = describe_changes(current, reported); !changes.empty())
            std::fputs(std::format("mmproxy in the last minute: {}\n", changes).c_str(), stderr);
        reported = current;
    }
    if (ready < 0)
        throw_socket_error("wait for shutdown");
    for (auto& thread : threads)
        thread.request_stop();
    return descriptors[1].revents != 0 ? 1 : 0;
}

} // namespace
} // namespace erikslund::mmproxy

int main(int argc, char** argv) {
    using namespace erikslund::mmproxy;
    try {
        const auto only_argument = argc == 2 ? std::string_view(argv[1]) : std::string_view{};
        if (only_argument == "--help" || only_argument == "-h") {
            const auto help = usage();
            std::fwrite(help.data(), 1, help.size(), stdout);
            return 0;
        }
        if (only_argument == "--version") {
            std::puts("erikslund-mmproxy " MMPROXY_VERSION);
            return 0;
        }
        raise_open_file_limit();
        return supervise(parse_config(std::span(argv + 1, static_cast<std::size_t>(argc - 1))));
    } catch (const std::exception& error) {
        std::fprintf(stderr, "mmproxy: %s\n", error.what());
        return 1;
    }
}
