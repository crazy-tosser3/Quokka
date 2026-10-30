#include "core/routing.hpp"

#include <algorithm>
#include <deque>
#include <set>

namespace routing {
namespace {

constexpr char SIGN_DOMAIN[] = "quokka-node-info-v1";
constexpr std::size_t SIGNATURE_SIZE = 64;

void put_u16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(uint8_t(value >> 8));
    out.push_back(uint8_t(value));
}

std::vector<uint8_t> signed_message(const uint8_t* body, std::size_t size) {
    std::vector<uint8_t> out(SIGN_DOMAIN, SIGN_DOMAIN + sizeof(SIGN_DOMAIN) - 1);
    out.insert(out.end(), body, body + size);
    return out;
}

class Reader {
public:
    Reader(const uint8_t* data, std::size_t size) : cursor_(data), left_(size) {}

    bool bytes(uint8_t* out, std::size_t size) {
        if (left_ < size) return false;
        std::copy_n(cursor_, size, out);
        cursor_ += size;
        left_ -= size;
        return true;
    }
    template <std::size_t N>
    bool array(std::array<uint8_t, N>& out) { return bytes(out.data(), N); }
    bool u8(uint8_t& out) { return bytes(&out, 1); }
    bool u16(uint16_t& out) {
        uint8_t raw[2];
        if (!bytes(raw, 2)) return false;
        out = static_cast<uint16_t>((raw[0] << 8) | raw[1]);
        return true;
    }
    bool u64(uint64_t& out) {
        uint8_t raw[8];
        if (!bytes(raw, 8)) return false;
        out = 0;
        for (const uint8_t byte : raw) out = (out << 8) | byte;
        return true;
    }
    bool empty() const { return left_ == 0; }

private:
    const uint8_t* cursor_;
    std::size_t left_;
};

}

bool is_valid_name(const std::string& name) {
    if (name.size() > MAX_NAME_SIZE) return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        const auto byte = static_cast<unsigned char>(c);
        return byte >= 0x20 && byte != 0x7F;
    });
}

std::vector<uint8_t> encode_node_info(const NodeInfo& info, const identity::NodeIdentity& node) {
    std::vector<uint8_t> body;
    body.insert(body.end(), info.signing_key.begin(), info.signing_key.end());
    body.insert(body.end(), info.static_key.begin(), info.static_key.end());
    for (int shift = 56; shift >= 0; shift -= 8) body.push_back(uint8_t(info.sequence >> shift));
    body.push_back(static_cast<uint8_t>(info.name.size()));
    body.insert(body.end(), info.name.begin(), info.name.end());
    put_u16(body, static_cast<uint16_t>(info.neighbors.size()));
    for (const NodeId& neighbor : info.neighbors) body.insert(body.end(), neighbor.begin(), neighbor.end());
    body.push_back(static_cast<uint8_t>(info.services.size()));
    for (const Service& service : info.services) {
        body.push_back(static_cast<uint8_t>(service.proto));
        put_u16(body, service.port);
    }
    const auto message = signed_message(body.data(), body.size());
    const auto signature = identity::sign(node, message.data(), message.size());
    body.insert(body.end(), signature.begin(), signature.end());
    return body;
}

std::optional<NodeInfo> decode_node_info(const uint8_t* data, std::size_t size) {
    if (size < SIGNATURE_SIZE) return std::nullopt;
    const std::size_t body_size = size - SIGNATURE_SIZE;

    NodeInfo info;
    Reader reader(data, body_size);
    uint8_t name_size = 0;
    uint16_t neighbor_count = 0;
    uint8_t service_count = 0;
    if (!reader.array(info.signing_key) || !reader.array(info.static_key) || !reader.u64(info.sequence) ||
        !reader.u8(name_size) || name_size > MAX_NAME_SIZE) {
        return std::nullopt;
    }
    info.name.resize(name_size);
    if (!reader.bytes(reinterpret_cast<uint8_t*>(info.name.data()), name_size) || !is_valid_name(info.name) ||
        !reader.u16(neighbor_count) || neighbor_count > MAX_NEIGHBORS) {
        return std::nullopt;
    }
    info.neighbors.resize(neighbor_count);
    for (NodeId& neighbor : info.neighbors) {
        if (!reader.array(neighbor)) return std::nullopt;
    }
    if (!reader.u8(service_count) || service_count > MAX_SERVICES) return std::nullopt;
    info.services.resize(service_count);
    for (Service& service : info.services) {
        uint8_t proto = 0;
        if (!reader.u8(proto) || proto > static_cast<uint8_t>(ServiceProto::Tcp) ||
            !reader.u16(service.port) || service.port == 0) {
            return std::nullopt;
        }
        service.proto = static_cast<ServiceProto>(proto);
    }
    if (!reader.empty()) return std::nullopt;

    identity::Signature signature;
    std::copy_n(data + body_size, SIGNATURE_SIZE, signature.begin());
    const auto message = signed_message(data, body_size);
    if (!identity::verify(info.signing_key, message.data(), message.size(), signature)) return std::nullopt;
    return info;
}

Database::InsertResult Database::insert(const uint8_t* data, std::size_t size, Clock::time_point now) {
    auto info = decode_node_info(data, size);
    if (!info) return InsertResult::Invalid;

    const NodeId id = info->id();
    if (id == self_) return InsertResult::Stale;  // о себе мы знаем лучше всех

    auto it = entries_.find(id);
    if (it != entries_.end()) {
        if (info->sequence <= it->second.info.sequence) return InsertResult::Stale;
        if (now - it->second.updated_at < MIN_UPDATE_INTERVAL) {
            if (info->sequence > it->second.deferred_sequence) {
                it->second.deferred.assign(data, data + size);
                it->second.deferred_sequence = info->sequence;
            }
            return InsertResult::Throttled;
        }
    } else if (entries_.size() >= MAX_NODES) {
        return InsertResult::Full;
    }
    entries_[id] = Entry{std::move(*info), std::vector<uint8_t>(data, data + size), now, {}, 0};
    return InsertResult::Updated;
}

void Database::set_self(const std::vector<uint8_t>& encoded, const NodeInfo& info) {
    entries_[self_] = Entry{info, encoded, Clock::now(), {}, 0};
}

std::vector<std::vector<uint8_t>> Database::apply_deferred(Clock::time_point now) {
    std::vector<std::vector<uint8_t>> applied;
    for (auto& [id, entry] : entries_) {
        if (entry.deferred.empty() || now - entry.updated_at < MIN_UPDATE_INTERVAL) continue;
        auto info = decode_node_info(entry.deferred.data(), entry.deferred.size());
        std::vector<uint8_t> encoded = std::move(entry.deferred);
        entry.deferred.clear();
        entry.deferred_sequence = 0;
        if (!info || info->sequence <= entry.info.sequence) continue;
        entry.info = std::move(*info);
        entry.encoded = encoded;
        entry.updated_at = now;
        applied.push_back(std::move(encoded));
    }
    return applied;
}

std::vector<NodeId> Database::expire(Clock::time_point now) {
    std::vector<NodeId> removed;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->first != self_ && now - it->second.updated_at > EXPIRY) {
            removed.push_back(it->first);
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    return removed;
}

const NodeInfo* Database::find(const NodeId& id) const {
    const auto it = entries_.find(id);
    return it == entries_.end() ? nullptr : &it->second.info;
}

std::map<NodeId, Route> Database::compute_routes(const std::vector<NodeId>& direct) const {
    std::map<NodeId, Route> routes;
    std::deque<NodeId> queue;

    // Соседи self упорядочены, поэтому при равной длине пути выбор предсказуем
    std::vector<NodeId> first_hops = direct;
    std::sort(first_hops.begin(), first_hops.end());
    for (const NodeId& neighbor : first_hops) {
        if (neighbor == self_) continue;
        routes[neighbor] = Route{neighbor, 1};
        queue.push_back(neighbor);
    }

    while (!queue.empty()) {
        const NodeId current = queue.front();
        queue.pop_front();
        const NodeInfo* info = find(current);
        if (!info) continue;
        const Route route = routes[current];

        std::vector<NodeId> next = info->neighbors;
        std::sort(next.begin(), next.end());
        for (const NodeId& neighbor : next) {
            if (neighbor == self_ || routes.contains(neighbor)) continue;
            const NodeInfo* other = find(neighbor);
            if (!other) continue;
            // Связь настоящая, только если о ней сообщили оба конца
            if (std::find(other->neighbors.begin(), other->neighbors.end(), current) == other->neighbors.end()) continue;
            routes[neighbor] = Route{route.next_hop, route.hops + 1};
            queue.push_back(neighbor);
        }
    }
    return routes;
}

}
