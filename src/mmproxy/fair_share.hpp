#pragma once
// Keep one client network from taking every TCP connection slot once the proxy is nearly full.

#include <cstddef>
#include <map>
#include <mutex>

#include "mmproxy/address.hpp"

namespace erikslund::mmproxy {

class FairShare {
public:
    explicit FairShare(std::size_t capacity);

    [[nodiscard]] bool admit(const IpAddress& address);
    // Return a connection that admit() counted.
    void release(const IpAddress& address);

private:
    std::mutex lock_;
    std::map<IpAddress, std::size_t> connections_;
    std::size_t total_ = 0;
    std::size_t contended_at_;
    std::size_t share_;
};

} // namespace erikslund::mmproxy
