#pragma once
// Find the cgroup v2 directories whose limits apply to this process.

#include <filesystem>
#include <vector>

namespace erikslund::mmproxy {

[[nodiscard]] std::vector<std::filesystem::path> cgroup_directories();

} // namespace erikslund::mmproxy
