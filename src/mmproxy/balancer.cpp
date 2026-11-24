#include "mmproxy/balancer.hpp"

#include <cstdint>
#include <utility>

#include <sys/eventfd.h>
#include <unistd.h>

#include "mmproxy/socket.hpp"

namespace erikslund::mmproxy {

Balancer::Balancer(std::size_t workers) : slots_(workers) {
    for (auto& slot : slots_) {
        slot.wakeup = FileDescriptor(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
        if (!slot.wakeup)
            throw_system_error("open worker handoff descriptor");
    }
}

std::size_t Balancer::choose(std::size_t accepting_worker) const noexcept {
    std::size_t chosen = accepting_worker;
    auto fewest = slots_[accepting_worker].connections.load(std::memory_order_relaxed);
    for (std::size_t worker = 0; worker < slots_.size(); ++worker) {
        const auto connections = slots_[worker].connections.load(std::memory_order_relaxed);
        if (connections < fewest) {
            chosen = worker;
            fewest = connections;
        }
    }
    return chosen;
}

void Balancer::hand_off(std::size_t worker, Handoff handoff) {
    auto& slot = slots_[worker];
    slot.connections.fetch_add(1, std::memory_order_relaxed);
    {
        const std::lock_guard guard(slot.lock);
        slot.inbox.push_back(std::move(handoff));
    }
    constexpr std::uint64_t kOneClient = 1;
    [[maybe_unused]] const auto written =
        ::write(slot.wakeup.get(), &kOneClient, sizeof(kOneClient));
}

std::vector<Handoff> Balancer::take_handoffs(std::size_t worker) {
    auto& slot = slots_[worker];
    std::uint64_t queued = 0;
    [[maybe_unused]] const auto drained = ::read(slot.wakeup.get(), &queued, sizeof(queued));
    std::vector<Handoff> handoffs;
    const std::lock_guard guard(slot.lock);
    handoffs.swap(slot.inbox);
    return handoffs;
}

void Balancer::opened(std::size_t worker) noexcept {
    slots_[worker].connections.fetch_add(1, std::memory_order_relaxed);
}

void Balancer::closed(std::size_t worker) noexcept {
    slots_[worker].connections.fetch_sub(1, std::memory_order_relaxed);
}

int Balancer::inbox_descriptor(std::size_t worker) const noexcept {
    return slots_[worker].wakeup.get();
}

} // namespace erikslund::mmproxy
