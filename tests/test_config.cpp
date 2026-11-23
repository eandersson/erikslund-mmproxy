#include <doctest/doctest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include <sys/resource.h>

#include "mmproxy/config.hpp"

namespace erikslund::mmproxy {
namespace {

constexpr std::string_view kRelay = "192.0.2.25/32";
constexpr std::string_view kBackend = "127.0.0.1:3333";

Config parse(std::initializer_list<std::string_view> arguments) {
    std::vector<std::string> storage(arguments.begin(), arguments.end());
    std::vector<char*> pointers;
    for (auto& argument : storage)
        pointers.push_back(argument.data());
    return parse_config(pointers);
}

// Write a temporary allowlist and delete it when the test ends.
class AllowlistFile {
public:
    explicit AllowlistFile(std::string_view content)
        : path_(std::filesystem::temp_directory_path() / "mmproxy-test-allowlist.txt") {
        std::ofstream(path_, std::ios::binary) << content;
    }
    ~AllowlistFile() { std::filesystem::remove(path_); }
    AllowlistFile(const AllowlistFile&) = delete;
    AllowlistFile& operator=(const AllowlistFile&) = delete;

    [[nodiscard]] std::string path() const { return path_.string(); }

private:
    std::filesystem::path path_;
};

// Lower the soft descriptor limit for one test, then restore it.
class DescriptorLimit {
public:
    explicit DescriptorLimit(rlim_t soft_limit) {
        REQUIRE(::getrlimit(RLIMIT_NOFILE, &original_) == 0);
        REQUIRE(original_.rlim_max >= soft_limit);
        rlimit lowered = original_;
        lowered.rlim_cur = soft_limit;
        REQUIRE(::setrlimit(RLIMIT_NOFILE, &lowered) == 0);
    }
    ~DescriptorLimit() { ::setrlimit(RLIMIT_NOFILE, &original_); }
    DescriptorLimit(const DescriptorLimit&) = delete;
    DescriptorLimit& operator=(const DescriptorLimit&) = delete;

private:
    rlimit original_{};
};

TEST_CASE("Configuration requires a trusted relay and a backend") {
    CHECK_THROWS_WITH_AS(parse({"--backend-v4", kBackend}), doctest::Contains("trusted relay"),
                         ConfigError);
    CHECK_THROWS_WITH_AS(parse({"--allow", kRelay}), doctest::Contains("backend"), ConfigError);
}

TEST_CASE("Backends must stay on loopback") {
    CHECK_THROWS_WITH_AS(parse({"--allow", kRelay, "--backend-v4", "192.0.2.30:3333"}),
                         doctest::Contains("loopback"), ConfigError);
    CHECK_THROWS_WITH_AS(parse({"--allow", kRelay, "--backend-v6", "[2001:db8::1]:3333"}),
                         doctest::Contains("loopback"), ConfigError);
}

TEST_CASE("Each backend option accepts only its own address family") {
    CHECK_THROWS_AS(parse({"--allow", kRelay, "--backend-v4", "[::1]:3333"}), ConfigError);
    CHECK_THROWS_AS(parse({"--allow", kRelay, "--backend-v6", kBackend}), ConfigError);
}

TEST_CASE("The listener may not overlap a backend, even as a wildcard") {
    CHECK_THROWS_WITH_AS(parse({"--allow", kRelay, "--backend-v4", kBackend, "--listen", kBackend}),
                         doctest::Contains("overlaps a backend"), ConfigError);
    CHECK_THROWS_WITH_AS(
        parse({"--allow", kRelay, "--backend-v4", kBackend, "--listen", "0.0.0.0:3333"}),
        doctest::Contains("overlaps a backend"), ConfigError);
}

TEST_CASE("-listeners above the worker maximum runs the most workers, --workers refuses it") {
    CHECK(parse({"--allow", kRelay, "--backend-v4", kBackend, "-p", "udp", "-listeners", "1000"})
              .workers == 64);
    CHECK_THROWS_WITH_AS(parse({"--allow", kRelay, "--backend-v4", kBackend, "--workers", "65"}),
                         doctest::Contains("from 1 to 64"), ConfigError);
    CHECK_THROWS_AS(parse({"--allow", kRelay, "--backend-v4", kBackend, "-listeners", "0"}),
                    ConfigError);
}

TEST_CASE("Options accept --name=value") {
    const auto config = parse({"--allow=192.0.2.25/32", "--backend-v4=127.0.0.1:3333",
                               "--idle-timeout-ms=0", "--max-connections=100"});
    CHECK(config.trusted.contains(parse_ip_address("192.0.2.25").value()));
    CHECK(config.idle_timeout == std::chrono::milliseconds::zero());
    CHECK(config.max_connections <= 100);
}

TEST_CASE("The relay user timeout is off unless --user-timeout-ms sets it") {
    CHECK(parse({"--allow", kRelay, "--backend-v4", kBackend}).user_timeout ==
          std::chrono::milliseconds::zero());
    CHECK(parse({"--allow", kRelay, "--backend-v4", kBackend, "--user-timeout-ms", "0"})
              .user_timeout == std::chrono::milliseconds::zero());
    CHECK(parse({"--allow", kRelay, "--backend-v4", kBackend, "--user-timeout-ms=120000"})
              .user_timeout == std::chrono::minutes(2));
    for (const auto value : {"-1", "86400001", "1.5"}) {
        CHECK_THROWS_AS(
            parse({"--allow", kRelay, "--backend-v4", kBackend, "--user-timeout-ms", value}),
            ConfigError);
    }
}

TEST_CASE("Allowlist files accept comments, blank lines, spaces and CRLF") {
    const AllowlistFile allowlist("# relays\r\n192.0.2.25/32\r\n\r\n  2001:db8:42::/48  # v6\n");
    const auto config = parse({"--allowed-subnets", allowlist.path(), "--backend-v4", kBackend});
    CHECK(config.trusted.contains(parse_ip_address("192.0.2.25").value()));
    CHECK(config.trusted.contains(parse_ip_address("2001:db8:42::7").value()));
    CHECK_FALSE(config.trusted.contains(parse_ip_address("192.0.2.26").value()));
}

TEST_CASE("An allowlist that covers this host needs --allow-local-relays") {
    for (const auto relay : {"127.0.0.1/32", "127.0.0.0/8", "::1", "10.42.0.0/24"}) {
        CHECK_THROWS_WITH_AS(
            parse({"--allow", relay, "--backend-v4", kBackend, "--listen", "10.42.0.10:8443"}),
            doctest::Contains("--allow-local-relays"), ConfigError);
    }
    const auto config = parse({"--allow", "127.0.0.1/32", "--backend-v4", kBackend,
                               "--allow-local-relays"});
    CHECK(config.allow_local_relays);
}

TEST_CASE("A /0 relay entry needs --allow-any-relay") {
    for (const auto relay : {"0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96"}) {
        CHECK_THROWS_WITH_AS(parse({"--allow", relay, "--backend-v4", kBackend}),
                             doctest::Contains("--allow-any-relay"), ConfigError);
    }
    const auto config = parse({"--allow", "0.0.0.0/0", "--backend-v4", kBackend,
                               "--allow-any-relay"});
    CHECK(config.allow_any_relay);
}

TEST_CASE("--allow-any-relay waives only the /0 entries themselves") {
    // A loopback entry still needs --allow-local-relays, with or without a /0 beside it.
    CHECK_THROWS_WITH_AS(
        parse({"--allow", "127.0.0.0/8", "--backend-v4", kBackend, "--allow-any-relay"}),
        doctest::Contains("--allow-local-relays"), ConfigError);
    CHECK_THROWS_WITH_AS(parse({"--allow", "::/0", "--allow", "127.0.0.1", "--backend-v4",
                                kBackend, "--allow-any-relay"}),
                         doctest::Contains("--allow-local-relays"), ConfigError);
    // An IPv4 /0 does not excuse an IPv6 link-local entry.
    CHECK_THROWS_WITH_AS(parse({"--allow", "0.0.0.0/0", "--allow", "fe80::1", "--backend-v4",
                                kBackend, "--allow-any-relay"}),
                         doctest::Contains("link-local"), ConfigError);
}

TEST_CASE("A wildcard listener still refuses a loopback allowlist") {
    CHECK_THROWS_WITH_AS(
        parse({"--allow", "127.0.0.1", "--backend-v4", kBackend, "--listen", "0.0.0.0:8443"}),
        doctest::Contains("--allow-local-relays"), ConfigError);
}

TEST_CASE("Flags reject a value instead of calling themselves unknown") {
    for (const auto flag : {"--allow-local-relays=true", "--allow-any-relay=1"}) {
        CHECK_THROWS_WITH_AS(parse({"--allow", kRelay, "--backend-v4", kBackend, flag}),
                             doctest::Contains("takes no value"), ConfigError);
    }
}

TEST_CASE("IPv6 link-local relay entries are refused") {
    for (const auto relay : {"fe80::1", "fe80::/64", "fe80::/9"}) {
        CHECK_THROWS_WITH_AS(parse({"--allow", relay, "--backend-v4", kBackend}),
                             doctest::Contains("link-local"), ConfigError);
    }
}

TEST_CASE("Relay entries with host bits set are refused with a hint") {
    CHECK_THROWS_WITH_AS(parse({"--allow", "10.42.0.5/3", "--backend-v4", kBackend}),
                         doctest::Contains("host bits are zero"), ConfigError);
}

TEST_CASE("The PROXY header limit stays between the v1 maximum and 64 KiB") {
    CHECK(parse({"--allow", kRelay, "--backend-v4", kBackend}).max_header_bytes == 4096);
    CHECK(parse({"--allow", kRelay, "--backend-v4", kBackend, "--max-header-bytes", "107"})
              .max_header_bytes == 107);
    CHECK_THROWS_AS(
        parse({"--allow", kRelay, "--backend-v4", kBackend, "--max-header-bytes", "106"}),
        ConfigError);
    CHECK_THROWS_AS(
        parse({"--allow", kRelay, "--backend-v4", kBackend, "--max-header-bytes", "65552"}),
        ConfigError);
}

TEST_CASE("Allowlist errors name the file and line") {
    const AllowlistFile allowlist("192.0.2.25/32\nnot-an-address\n");
    CHECK_THROWS_WITH_AS(parse({"--allowed-subnets", allowlist.path(), "--backend-v4", kBackend}),
                         doctest::Contains(":2"), ConfigError);
}

TEST_CASE("The descriptor limit caps TCP tunnels at six descriptors each") {
    const DescriptorLimit limit(1000);
    const auto config = parse({"--allow", kRelay, "--backend-v4", kBackend, "--workers", "1"});
    // 64 reserved plus 19 for the worker (listener, epoll, eventfd, 8 cached pipes) leaves 917
    // for tunnels.
    CHECK(config.max_connections == 152);
}

TEST_CASE("Workers split one grown-pipe budget instead of each taking their own") {
    const auto one_worker = parse({"--allow", kRelay, "--backend-v4", kBackend, "--workers", "1"});
    const auto two_workers = parse({"--allow", kRelay, "--backend-v4", kBackend, "--workers", "2"});
    // The budget is half the per-user pipe pages, whatever the worker count.
    CHECK(two_workers.streaming_pipes == one_worker.streaming_pipes);
}

TEST_CASE("Default TCP workers stay between one and eight") {
    const auto config = parse({"--allow", kRelay, "--backend-v4", kBackend});
    CHECK(config.workers >= 1);
    CHECK(config.workers <= 8);
}

} // namespace
} // namespace erikslund::mmproxy
