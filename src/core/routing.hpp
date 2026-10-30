#pragma once

#include "core/config.hpp"
#include "core/identity.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

// Карта сети (link-state): каждый узел подписывает сведения о себе и своих соседях,
// сведения рассылаются всем, а маршруты каждый считает сам. Так подделать можно только
// рассказ о себе, а связь считается настоящей, лишь если о ней сообщили оба её конца.
namespace routing {

using identity::NodeId;

inline constexpr std::size_t MAX_NODES = 4096;
inline constexpr std::size_t MAX_NEIGHBORS = 256;
inline constexpr std::size_t MAX_NAME_SIZE = 32;

struct NodeInfo {
    identity::PublicKey signing_key{};
    noise::Key static_key{};
    uint64_t sequence{0};
    std::string name;
    std::vector<NodeId> neighbors;
    std::vector<Service> services;

    NodeId id() const { return identity::node_id_of(signing_key); }
};

// Подписывает и кодирует сведения об узле
std::vector<uint8_t> encode_node_info(const NodeInfo& info, const identity::NodeIdentity& node);
// nullopt при неверной подписи или формате
std::optional<NodeInfo> decode_node_info(const uint8_t* data, std::size_t size);

// Имя приходит от других узлов и попадает в лог: только печатные символы
bool is_valid_name(const std::string& name);

struct Route {
    NodeId next_hop{};
    std::size_t hops{0};
};

class Database {
public:
    using Clock = std::chrono::steady_clock;

    enum class InsertResult { Updated, Stale, Invalid, Throttled, Full };

    // Сведения устаревают, если их не обновляли: узел мог исчезнуть
    static constexpr auto EXPIRY = std::chrono::seconds(180);
    // Участник не должен иметь возможность заставить всю сеть бесконечно пересылать его сведения.
    // Слишком частое обновление откладывается: из очереди применяется только самое новое.
    static constexpr auto MIN_UPDATE_INTERVAL = std::chrono::milliseconds(100);

    explicit Database(NodeId self) : self_(self) {}

    InsertResult insert(const uint8_t* data, std::size_t size, Clock::time_point now);
    void set_self(const std::vector<uint8_t>& encoded, const NodeInfo& info);

    // Применяет отложенные обновления, которым пришло время. Возвращает их, чтобы разослать дальше
    std::vector<std::vector<uint8_t>> apply_deferred(Clock::time_point now);

    // Возвращает идентификаторы удалённых узлов
    std::vector<NodeId> expire(Clock::time_point now);

    const NodeInfo* find(const NodeId& id) const;
    std::size_t size() const { return entries_.size(); }

    template <class Fn>
    void for_each(Fn&& fn) const {
        for (const auto& [id, entry] : entries_) fn(id, entry.info, entry.encoded);
    }

    // Кратчайшие пути из self: учитываются только связи, о которых сообщили обе стороны.
    // direct — соседи, готовые принимать трафик прямо сейчас.
    std::map<NodeId, Route> compute_routes(const std::vector<NodeId>& direct) const;

private:
    struct Entry {
        NodeInfo info;
        std::vector<uint8_t> encoded;
        Clock::time_point updated_at;
        std::vector<uint8_t> deferred;
        uint64_t deferred_sequence{0};
    };

    NodeId self_;
    std::map<NodeId, Entry> entries_;
};

}
