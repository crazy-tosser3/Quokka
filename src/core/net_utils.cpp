#include "core/net_utils.hpp"

#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/resource.h>

std::vector<boost::asio::ip::address_v4> local_ipv4_interfaces() {
    std::vector<boost::asio::ip::address_v4> result;

    struct ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0) return result;

    for (auto* iface = interfaces; iface != nullptr; iface = iface->ifa_next) {
        if (!iface->ifa_addr || iface->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        const auto* addr = reinterpret_cast<const sockaddr_in*>(iface->ifa_addr);
        result.emplace_back(ntohl(addr->sin_addr.s_addr));
    }

    freeifaddrs(interfaces);
    return result;
}

void raise_file_limit() {
    struct rlimit limit{};
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur == limit.rlim_max) return;
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
        // macOS не разрешает больше OPEN_MAX, даже если жёсткий лимит "unlimited"
        limit.rlim_cur = 10240;
        setrlimit(RLIMIT_NOFILE, &limit);
    }
}
