#include "mmproxy/config.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mmproxy/cgroup.hpp"
#include "mmproxy/number.hpp"
#include "mmproxy/proxy_protocol.hpp"

namespace erikslund::mmproxy {
namespace {

constexpr int kMaxWorkers = 64;
constexpr unsigned kMaxDefaultWorkers = 8;
constexpr int kMaxConnections = 65'536;
constexpr int kMaxTimeoutMs = 86'400'000;
constexpr int kMinHeaderBytesLimit = static_cast<int>(kMaxProxyV1HeaderSize);
constexpr int kMaxHeaderBytesLimit = static_cast<int>(kMaxProxyHeaderSize);
constexpr int kSecondsToMilliseconds = 1000;
constexpr rlim_t kReservedDescriptors = 64;
constexpr rlim_t kDescriptorsPerWorker = 3;
constexpr rlim_t kDescriptorsPerPipe = 2;
constexpr std::string_view kPipeUserPagesSoftPath = "/proc/sys/fs/pipe-user-pages-soft";
constexpr std::size_t kDefaultPipeUserPagesSoft = 16'384;
constexpr std::size_t kFallbackPageBytes = 4096;
constexpr std::size_t kStreamingBudgetDivisor = 2;

int read_integer(std::string_view value, std::string_view option, int minimum, int maximum) {
    const auto number = parse_number<int>(value);
    if (!number || *number < minimum || *number > maximum)
        throw ConfigError(
            std::format("{} expects an integer from {} to {}", option, minimum, maximum));
    return *number;
}

std::size_t read_size(std::string_view value, std::string_view option, int minimum, int maximum) {
    return static_cast<std::size_t>(read_integer(value, option, minimum, maximum));
}

std::chrono::milliseconds read_timeout(std::string_view value, std::string_view option,
                                       int minimum) {
    return std::chrono::milliseconds(read_integer(value, option, minimum, kMaxTimeoutMs));
}

Transport read_transport(std::string_view value) {
    if (value == "tcp")
        return Transport::Tcp;
    if (value == "udp")
        return Transport::Udp;
    throw ConfigError("--protocol expects tcp or udp");
}

Endpoint read_endpoint(std::string_view value, std::string_view option) {
    const auto endpoint = parse_endpoint(value);
    if (!endpoint || endpoint->port == 0)
        throw ConfigError(std::format("{} expects a numeric IP and nonzero port", option));
    return *endpoint;
}

Endpoint read_backend(std::string_view value, std::string_view option, int family) {
    const auto endpoint = read_endpoint(value, option);
    if (endpoint.address.family != family)
        throw ConfigError(std::format("{} expects an address of the configured IP family", option));
    if (!endpoint.address.is_loopback())
        throw ConfigError(std::format("{} requires a loopback address", option));
    return endpoint;
}

constexpr std::string_view kTrustEntryHint =
    "use a numeric IP, or a CIDR whose host bits are zero, such as 10.42.0.0/24";

void add_trusted(TrustList& trusted, std::string_view entry) {
    if (!trusted.add(entry))
        throw ConfigError(std::format("invalid relay entry '{}': {}", entry, kTrustEntryHint));
}

void read_trusted_file(TrustList& trusted, std::string_view path) {
    std::ifstream input{std::string(path)};
    if (!input)
        throw ConfigError(std::format("could not open relay allowlist '{}'", path));
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        auto entry = std::string_view(line).substr(0, line.find('#'));
        const auto first = entry.find_first_not_of(" \t\r");
        if (first == std::string_view::npos)
            continue;
        entry = entry.substr(first, entry.find_last_not_of(" \t\r") - first + 1);
        if (!trusted.add(entry))
            throw ConfigError(std::format("invalid relay entry at {}:{}: {}", path, line_number,
                                          kTrustEntryHint));
    }
    if (input.bad())
        throw ConfigError(std::format("could not read relay allowlist '{}'", path));
}

std::optional<unsigned int> read_cpu_limit(const std::filesystem::path& path) {
    std::ifstream file(path);
    std::string quota_text;
    std::uint64_t period = 0;
    if (!(file >> quota_text >> period) || quota_text == "max" || period == 0)
        return std::nullopt;
    const auto quota = parse_number<std::uint64_t>(quota_text);
    if (!quota)
        return std::nullopt;
    return static_cast<unsigned int>(std::max<std::uint64_t>(1, (*quota + period - 1) / period));
}

std::optional<unsigned int> cgroup_cpu_limit() {
    std::optional<unsigned int> tightest;
    for (const auto& directory : cgroup_directories()) {
        const auto limit = read_cpu_limit(directory / "cpu.max");
        if (limit && (!tightest || *limit < *tightest))
            tightest = limit;
    }
    return tightest;
}

unsigned int usable_cpu_count() {
    unsigned int cpus = std::thread::hardware_concurrency();
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (::sched_getaffinity(0, sizeof(allowed), &allowed) == 0)
        cpus = static_cast<unsigned int>(CPU_COUNT(&allowed));
    if (const auto limit = cgroup_cpu_limit())
        cpus = std::min(cpus, *limit);
    return std::max(cpus, 1U);
}

std::size_t read_streaming_pipe_budget() {
    std::size_t budget_pages = kDefaultPipeUserPagesSoft;
    if (std::ifstream file{std::string(kPipeUserPagesSoftPath)}; file) {
        std::size_t configured = 0;
        if (file >> configured)
            budget_pages = configured;
    }
    if (budget_pages == 0)
        return std::numeric_limits<std::size_t>::max();
    const long page_size = ::sysconf(_SC_PAGESIZE);
    const auto page_bytes = page_size > 0 ? static_cast<std::size_t>(page_size) : kFallbackPageBytes;
    return budget_pages * page_bytes / kStreamingBudgetDivisor / kStreamingPipeBytes;
}

bool listener_overlaps(const Endpoint& listener, const Endpoint& backend) {
    if (listener.address.family != backend.address.family || listener.port != backend.port)
        return false;
    return listener.address == backend.address || listener.address.is_wildcard();
}

std::vector<IpAddress> host_addresses() {
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0)
        return {};
    std::vector<IpAddress> addresses;
    for (const auto* entry = list; entry != nullptr; entry = entry->ifa_next) {
        if (entry->ifa_addr == nullptr)
            continue;
        const auto family = entry->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;
        sockaddr_storage storage{};
        std::memcpy(&storage, entry->ifa_addr,
                    family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
        if (const auto endpoint = from_socket_address(storage))
            addresses.push_back(endpoint->address);
    }
    ::freeifaddrs(list);
    return addresses;
}

bool trusts_this_host(const Config& config) {
    constexpr unsigned int kIpv4LoopbackBits = 8;
    constexpr unsigned int kSingleHostPrefixBits = 128;
    const auto covers = [&config](const IpAddress& address, unsigned int bits) {
        return config.trusted.overlaps(address, bits, TrustList::Everyone::Ignore);
    };
    if (covers(parse_ip_address("127.0.0.0").value(), kIpv4LoopbackBits) ||
        covers(parse_ip_address("::1").value(), kSingleHostPrefixBits))
        return true;
    const auto& listen = config.listen.address;
    if (!listen.is_wildcard() && covers(listen, kSingleHostPrefixBits))
        return true;
    return std::ranges::any_of(host_addresses(), [&covers](const IpAddress& address) {
        return covers(address, kSingleHostPrefixBits);
    });
}

bool trusts_link_local(const TrustList& trusted) {
    constexpr unsigned int kLinkLocalBits = 10;
    return trusted.overlaps(parse_ip_address("fe80::").value(), kLinkLocalBits,
                            TrustList::Everyone::Ignore);
}

void validate(const Config& config) {
    if (config.trusted.empty())
        throw ConfigError("configure at least one trusted relay with --allow or --allowed-subnets");
    if (!config.backend_ipv4 && !config.backend_ipv6)
        throw ConfigError("configure a loopback backend with --backend-v4 or --backend-v6");
    for (const auto* backend : {&config.backend_ipv4, &config.backend_ipv6}) {
        if (*backend && listener_overlaps(config.listen, **backend))
            throw ConfigError("the proxy listener overlaps a backend address");
    }
    if (config.trusted.trusts_everyone() && !config.allow_any_relay)
        throw ConfigError("a /0 relay entry lets every host claim client addresses; add "
                          "--allow-any-relay to confirm");
    if (trusts_this_host(config) && !config.allow_local_relays)
        throw ConfigError("the relay allowlist covers this host, so any local process could act "
                          "as a relay; add --allow-local-relays for a relay on this host");
    if (trusts_link_local(config.trusted))
        throw ConfigError("IPv6 link-local relay entries (fe80::/10) are not supported, because "
                          "the allowlist cannot tell links apart");
}

constexpr std::string_view kAllowLocalRelays = "--allow-local-relays";
constexpr std::string_view kAllowAnyRelay = "--allow-any-relay";

bool apply_flag(Config& config, std::string_view argument) {
    if (argument == kAllowLocalRelays)
        config.allow_local_relays = true;
    else if (argument == kAllowAnyRelay)
        config.allow_any_relay = true;
    else
        return false;
    return true;
}

std::string_view go_spelling(std::string_view option) {
    constexpr std::array<std::string_view, 6> kGoOnlyOptions = {"-l", "-4", "-6", "-p",
                                                                "-listeners", "-close-after"};
    if (option.starts_with("--") && std::ranges::contains(kGoOnlyOptions, option.substr(1)))
        return option.substr(1);
    return option;
}

void apply_option(Config& config, std::string_view option, std::string_view value) {
    if (option == "--listen" || option == "-l")
        config.listen = read_endpoint(value, option);
    else if (option == "--backend-v4" || option == "-4")
        config.backend_ipv4 = read_backend(value, option, AF_INET);
    else if (option == "--backend-v6" || option == "-6")
        config.backend_ipv6 = read_backend(value, option, AF_INET6);
    else if (option == "--allow")
        add_trusted(config.trusted, value);
    else if (option == "--allowed-subnets" || option == "-allowed-subnets")
        read_trusted_file(config.trusted, value);
    else if (option == "--protocol" || option == "-p")
        config.transport = read_transport(value);
    else if (option == "--workers")
        config.workers = read_size(value, option, 1, kMaxWorkers);
    else if (option == "-listeners")
        config.workers = std::min<std::size_t>(
            read_size(value, option, 1, std::numeric_limits<int>::max()), kMaxWorkers);
    else if (option == "--max-connections")
        config.max_connections = read_size(value, option, 1, kMaxConnections);
    else if (option == "--header-timeout-ms")
        config.header_timeout = read_timeout(value, option, 1);
    else if (option == "--connect-timeout-ms")
        config.connect_timeout = read_timeout(value, option, 1);
    else if (option == "--idle-timeout-ms")
        config.idle_timeout = read_timeout(value, option, 0);
    else if (option == "--udp-timeout-ms")
        config.udp_timeout = read_timeout(value, option, 1);
    else if (option == "--user-timeout-ms")
        config.user_timeout = read_timeout(value, option, 0);
    else if (option == "-close-after")
        config.udp_timeout = std::chrono::seconds(
            read_integer(value, option, 1, kMaxTimeoutMs / kSecondsToMilliseconds));
    else if (option == "--mark" || option == "-mark")
        config.backend_mark = read_integer(value, option, 0, std::numeric_limits<int>::max());
    else if (option == "--max-header-bytes")
        config.max_header_bytes =
            read_size(value, option, kMinHeaderBytesLimit, kMaxHeaderBytesLimit);
    else
        throw ConfigError(std::format("unknown option '{}'", option));
}

void apply_descriptor_limit(Config& config) {
    rlimit file_limit{};
    if (::getrlimit(RLIMIT_NOFILE, &file_limit) != 0 || file_limit.rlim_cur == RLIM_INFINITY)
        return;
    const bool tcp = config.transport == Transport::Tcp;
    const rlim_t cached_pipe_descriptors = tcp ? kCachedPipesPerWorker * kDescriptorsPerPipe : 0;
    const rlim_t reserved =
        kReservedDescriptors + (kDescriptorsPerWorker + cached_pipe_descriptors) * config.workers;
    const rlim_t per_connection = tcp ? kDescriptorsPerTcpConnection : kDescriptorsPerUdpFlow;
    if (file_limit.rlim_cur <= reserved)
        throw ConfigError("the open-file limit is too low to run the proxy");
    config.max_connections = std::min(
        config.max_connections,
        static_cast<std::size_t>((file_limit.rlim_cur - reserved) / per_connection));
}

} // namespace

Config parse_config(std::span<char*> arguments) {
    constexpr std::string_view kDefaultListen = "127.0.0.1:8443";
    Config config;
    config.listen = read_endpoint(kDefaultListen, "--listen");
    bool workers_given = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const auto argument = std::string_view(arguments[index]);
        if (apply_flag(config, argument))
            continue;
        const auto separator = argument.find('=');
        const auto option = go_spelling(argument.substr(0, separator));
        if (option == kAllowLocalRelays || option == kAllowAnyRelay)
            throw ConfigError(std::format("{} takes no value", option));
        workers_given |= option == "--workers" || option == "-listeners";
        if (separator != std::string_view::npos) {
            apply_option(config, option, argument.substr(separator + 1));
        } else {
            if (index + 1 == arguments.size())
                throw ConfigError(std::format("expected a value after '{}'", option));
            apply_option(config, option, arguments[++index]);
        }
    }
    validate(config);
    if (!workers_given && config.transport == Transport::Tcp)
        config.workers = std::clamp(usable_cpu_count(), 1U, kMaxDefaultWorkers);

    apply_descriptor_limit(config);
    if (!workers_given)
        config.workers = std::min(config.workers, config.max_connections);
    if (config.max_connections == 0 || config.workers > config.max_connections)
        throw ConfigError("the effective connection limit must allow at least one slot per worker");
    config.streaming_pipe_budget = read_streaming_pipe_budget();
    return config;
}

const std::optional<Endpoint>& backend_for(const Config& config, int family) {
    return family == AF_INET ? config.backend_ipv4 : config.backend_ipv6;
}

std::size_t worker_share(std::size_t total, std::size_t workers,
                         std::size_t worker_index) noexcept {
    return total / workers + (worker_index < total % workers ? 1 : 0);
}

std::string_view usage() {
    return R"(Usage: erikslund-mmproxy --allow CIDR --backend-v4 IP:PORT [options]

Required (repeat --allow or use a file, and configure at least one backend):
  --allow IP[/PREFIX]        Trust a relay IP or CIDR, IPv4 or IPv6
  --allowed-subnets FILE     Read relay CIDRs, one per line, with optional # comments
  --backend-v4 IP:PORT       Backend for IPv4 clients (loopback only)
  --backend-v6 '[IP]:PORT'   Backend for IPv6 clients (loopback only)

Options:
  --listen IP:PORT           Proxy listener (default 127.0.0.1:8443)
  --protocol tcp|udp         Proxy TCP or UDP (default tcp)
  --workers N                Listener workers (default: usable CPUs up to 8 for TCP, 1 for UDP)
  --max-connections N        Total TCP connections or UDP flows (default 65536)
  --header-timeout-ms N      TCP PROXY header deadline (default 2000)
  --connect-timeout-ms N     TCP backend connect deadline (default 3000)
  --idle-timeout-ms N        TCP idle timeout (default 300000, 0 disables)
  --udp-timeout-ms N         UDP flow idle timeout (default 60000)
  --user-timeout-ms N        Drop a relay that stops acknowledging data (default 0, off)
  --mark N                   Backend socket mark (default 0, kernel default)
  --max-header-bytes N       Largest TCP PROXY header with its TLVs (default 4096)
  --allow-local-relays       Accept an allowlist that covers this host's own addresses
  --allow-any-relay          Accept a /0 allowlist entry that trusts every host
  --version                  Print the version
  --help                     Show this help
)";
}

} // namespace erikslund::mmproxy
