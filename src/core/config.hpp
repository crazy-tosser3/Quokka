#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

enum class ServiceProto : uint8_t { Udp = 0, Tcp = 1 };

inline std::string_view to_string(ServiceProto proto) {
    return proto == ServiceProto::Udp ? "UDP" : "TCP";
}

// Порт на 127.0.0.1 этой машины, который она открывает остальной сети.
// Индекс сервиса в списке — его идентификатор в протоколе.
struct Service {
    ServiceProto proto{ServiceProto::Udp};
    uint16_t port{0};

    bool operator==(const Service&) const = default;
};

inline constexpr std::size_t MAX_SERVICES = 32;

// Какие чужие сервисы открыть у себя на 127.0.0.1 (--open)
struct OpenRule {
    std::string node;      // имя или начало идентификатора; пусто = любой узел
    uint16_t port{0};      // порт сервиса; 0 = все порты
    uint16_t local_port{0};  // 0 = тот же, что у сервиса
};

// Адрес, к которому узел подключается сам, не дожидаясь автопоиска (--peer)
struct PeerAddress {
    std::string host;
    uint16_t port{30002};
};

struct NodeConfig {
    std::string name;                 // имя узла для людей; не является доказательством личности

    std::vector<Service> services;    // свои порты, открытые сети
    std::vector<OpenRule> open_rules; // чужие порты, открываемые здесь
    std::vector<PeerAddress> peers;

    bool discovery = true;            // искать соседей через multicast
    std::string multicast_ip = "239.255.0.1";
    uint16_t discovery_port = 30001;

    uint16_t quic_port = 30002;       // UDP: приём соседей
    bool quic_port_explicit = false;  // занятый порт: ошибка, а не другой порт

    std::optional<std::size_t> max_listeners;  // предел входящих соединений; нет значения = без ограничений
};
