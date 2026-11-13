#pragma once

#include "core/identity.hpp"

#include <msquic.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Вход в сеть по короткому коду. Новое устройство подключается к узлу по отдельному ALPN,
// стороны доказывают знание кода через SPAKE2, и узел передаёт настоящий секрет сети.
namespace pairing {

// Сторона узла. Обратные вызовы идут в потоках MsQuic, поэтому состояние под мьютексом.
class Service {
public:
    explicit Service(const identity::Invite& network);
    ~Service();

    struct Issued {
        std::string code;
        std::chrono::seconds ttl;
        unsigned uses;
    };

    Issued issue(std::chrono::seconds ttl, unsigned uses);
    // Код, выданный другим участником и переданный нам, потому что до нас можно дотянуться
    void add(const std::string& code, std::chrono::seconds ttl, unsigned uses);
    bool active() const;

    // Для QUIC_LISTENER_EVENT_NEW_CONNECTION с ALPN входа
    QUIC_STATUS accept(HQUIC connection);

    struct Shared;

private:
    std::shared_ptr<Shared> shared_;
};

enum class Result { Ok, WrongCode, Unreachable };

struct ClientOutcome {
    Result result{Result::Unreachable};
    std::optional<identity::Invite> invite;
};

// Сторона нового устройства: блокирующий вызов, обращается к одному узлу
ClientOutcome join(const std::string& host, uint16_t port, const std::string& code);

// Узлы в локальной сети, у которых сейчас есть действующий код
struct LanHost {
    std::string host;
    uint16_t port{0};
};
std::vector<LanHost> find_on_lan(const std::string& multicast_ip, uint16_t discovery_port, std::chrono::seconds wait);

// Настройки MsQuic для входа: их мало, потому что соединение короткое
QUIC_SETTINGS quic_settings();

}
