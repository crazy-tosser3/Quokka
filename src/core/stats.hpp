#pragma once

#include "core/config.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct Stats {
    std::atomic<std::size_t> tcp_bridges{0};
    std::atomic<std::size_t> udp_flows{0};
    std::atomic<std::uint64_t> udp_packets_sent{0};
    std::atomic<std::uint64_t> udp_packets_received{0};
    std::atomic<std::uint64_t> udp_packets_dropped{0};
    std::atomic<std::uint64_t> relayed_datagrams{0};
    std::atomic<std::size_t> relayed_streams{0};
};

struct PeerStatus {
    std::string id;     // короткий идентификатор
    std::string name;
    std::size_t hops{0};  // 1 = прямой сосед
    std::optional<double> rtt_ms;  // только для прямых соседей
};

// Снимок состояния узла, который можно запрашивать из любого потока
struct NodeStatus {
    std::string id;
    uint16_t quic_port{0};
    std::vector<PeerStatus> peers;

    std::size_t tcp_bridges{0};
    std::size_t udp_flows{0};
    std::uint64_t udp_packets_sent{0};
    std::uint64_t udp_packets_received{0};
    std::uint64_t udp_packets_dropped{0};
    std::uint64_t relayed_datagrams{0};
    std::size_t relayed_streams{0};
};
