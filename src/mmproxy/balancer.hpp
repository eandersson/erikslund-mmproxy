#pragma once
// Pass newly accepted TCP clients to the worker holding the fewest connections.

#include <atomic>
#include <cstddef>
#include <mutex>
#include <vector>

#include "mmproxy/address.hpp"
#include "mmproxy/file_descriptor.hpp"

namespace erikslund::mmproxy {

struct Handoff {
    FileDescriptor client;
    Endpoint relay;
};

class Balancer {
public:
    explicit Balancer(std::size_t workers);

    [[nodiscard]] std::size_t choose(std::size_t accepting_worker) const noexcept;
    void hand_off(std::size_t worker, Handoff handoff);
    [[nodiscard]] std::vector<Handoff> take_handoffs(std::size_t worker);
    void opened(std::size_t worker) noexcept;
    void closed(std::size_t worker) noexcept;
    [[nodiscard]] int inbox_descriptor(std::size_t worker) const noexcept;

private:
    struct alignas(64) Slot {
        std::atomic_size_t connections{0};
        std::mutex lock;
        std::vector<Handoff> inbox;
        FileDescriptor wakeup;
    };

    std::vector<Slot> slots_;
};

} // namespace erikslund::mmproxy
