#include "mmproxy/cgroup.hpp"

#include <fstream>
#include <string>
#include <string_view>

namespace erikslund::mmproxy {
namespace {

constexpr std::string_view kCgroupRoot = "/sys/fs/cgroup";
constexpr std::string_view kUnifiedCgroupPrefix = "0::";

} // namespace

std::vector<std::filesystem::path> cgroup_directories() {
    std::ifstream membership("/proc/self/cgroup");
    std::string line;
    while (std::getline(membership, line)) {
        if (!line.starts_with(kUnifiedCgroupPrefix))
            continue;
        std::vector<std::filesystem::path> directories;
        std::filesystem::path group = line.substr(kUnifiedCgroupPrefix.size());
        for (;;) {
            directories.push_back(std::filesystem::path(kCgroupRoot) / group.relative_path());
            if (!group.has_relative_path())
                break;
            group = group.parent_path();
        }
        return directories;
    }
    return {};
}

} // namespace erikslund::mmproxy
