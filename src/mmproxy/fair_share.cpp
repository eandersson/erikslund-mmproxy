#include "mmproxy/fair_share.hpp"

#include <algorithm>

namespace erikslund::mmproxy {
namespace {

constexpr std::size_t kReserveDivisor = 8;
constexpr std::size_t kShareDivisor = 16;

} // namespace

FairShare::FairShare(std::size_t capacity)
    : contended_at_(capacity - capacity / kReserveDivisor),
      share_(std::max<std::size_t>(1, capacity / kShareDivisor)) {}

bool FairShare::admit(const IpAddress& address) {
    const auto source = client_source(address);
    const std::lock_guard guard(lock_);
    auto& held = connections_[source];
    if (total_ >= contended_at_ && held >= share_)
        return false;
    ++held;
    ++total_;
    return true;
}

void FairShare::release(const IpAddress& address) {
    const auto source = client_source(address);
    const std::lock_guard guard(lock_);
    const auto entry = connections_.find(source);
    if (entry == connections_.end())
        return;
    --total_;
    if (--entry->second == 0)
        connections_.erase(entry);
}

} // namespace erikslund::mmproxy
