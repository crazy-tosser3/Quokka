#pragma once

#include "core/config.hpp"
#include "core/identity.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

// Формат всего, что передаётся по сети. Описание — docs/ARCHITECTURE.md.
namespace protocol {

inline constexpr char ALPN[] = "quokka/2";

using identity::NodeId;

// Код закрытия QUIC-соединения между соседями
enum CloseCode : uint64_t {
    CLOSE_NORMAL = 0,
    CLOSE_FULL = 1,           // достигнут предел --listeners
    CLOSE_PROTOCOL_ERROR = 2,
    CLOSE_DUPLICATE = 3,      // с этим соседом уже есть соединение
    CLOSE_SELF = 4,           // подключились сами к себе
};

// --- Управляющий поток между соседями: [длина:2][тип:1][тело] ---

enum ControlType : uint8_t {
    CTRL_CHALLENGE = 1,  // [случайное число:32]
    CTRL_HELLO = 2,      // [ключ подписи:32][подпись:64]
    CTRL_READY = 3,      // соседа можно использовать для маршрутов
    CTRL_NODE_INFO = 4,  // сведения об узле, см. NodeInfo
};

inline constexpr std::size_t MAX_CONTROL_FRAME = 16 * 1024;

inline std::vector<uint8_t> make_control_frame(ControlType type, const uint8_t* body, std::size_t size) {
    const std::size_t length = size + 1;
    std::vector<uint8_t> out{uint8_t(length >> 8), uint8_t(length), static_cast<uint8_t>(type)};
    out.insert(out.end(), body, body + size);
    return out;
}

inline std::vector<uint8_t> hello_signed_data(const std::array<uint8_t, 32>& verifier_nonce,
                                              const std::array<uint8_t, 32>& signer_nonce) {
    constexpr char domain[] = "quokka-hello-v1";
    std::vector<uint8_t> out(domain, domain + sizeof(domain) - 1);
    out.insert(out.end(), verifier_nonce.begin(), verifier_nonce.end());
    out.insert(out.end(), signer_nonce.begin(), signer_nonce.end());
    return out;
}

// --- Датаграммы между соседями: первый байт — тип ---

enum DatagramType : uint8_t {
    DG_ROUTED = 0x10,  // заголовок ниже, затем [счётчик:8][шифротекст]
    DG_PING = 0x11,    // [тип][метка времени:8]
    DG_PONG = 0x12,    // копия PING с другим типом
};

// Маршрутизируемая датаграмма. TTL уменьшается на каждом узле, поэтому не входит в AAD.
struct RoutedHeader {
    uint8_t ttl{0};
    NodeId dst{};
    NodeId src{};
    uint8_t from_initiator{0};  // 1, если отправитель начал эту UDP-сессию
    uint32_t session{0};
};

inline constexpr std::size_t ROUTED_HEADER_SIZE = 2 + 16 + 16 + 1 + 4;
inline constexpr std::size_t DG_COUNTER_SIZE = 8;
inline constexpr uint8_t DEFAULT_TTL = 32;

inline void write_routed_header(uint8_t* out, const RoutedHeader& h) {
    out[0] = DG_ROUTED;
    out[1] = h.ttl;
    std::memcpy(out + 2, h.dst.data(), 16);
    std::memcpy(out + 18, h.src.data(), 16);
    out[34] = h.from_initiator;
    out[35] = uint8_t(h.session >> 24);
    out[36] = uint8_t(h.session >> 16);
    out[37] = uint8_t(h.session >> 8);
    out[38] = uint8_t(h.session);
}

inline std::optional<RoutedHeader> parse_routed_header(const std::vector<uint8_t>& pkt) {
    if (pkt.size() < ROUTED_HEADER_SIZE + DG_COUNTER_SIZE || pkt[0] != DG_ROUTED) return std::nullopt;
    RoutedHeader h;
    h.ttl = pkt[1];
    std::memcpy(h.dst.data(), pkt.data() + 2, 16);
    std::memcpy(h.src.data(), pkt.data() + 18, 16);
    h.from_initiator = pkt[34];
    h.session = (uint32_t(pkt[35]) << 24) | (uint32_t(pkt[36]) << 16) | (uint32_t(pkt[37]) << 8) | uint32_t(pkt[38]);
    return h;
}

// Подписанная часть заголовка: всё, кроме типа и TTL
inline const uint8_t* routed_aad(const uint8_t* pkt) { return pkt + 2; }
inline constexpr std::size_t ROUTED_AAD_SIZE = ROUTED_HEADER_SIZE - 2;

// Содержимое датаграммы внутри сквозного шифрования
enum InnerType : uint8_t {
    UDP_TO_TARGET = 0,  // к сервису получателя:   [тип][сервис][flow:4][данные]
    UDP_REPLY = 1,      // от сервиса отправителя: [тип][сервис][flow:4][данные]
};

struct UdpHeader {
    uint8_t type{0};
    uint8_t service{0};
    uint32_t flow{0};
};

inline constexpr std::size_t UDP_HEADER_SIZE = 6;

inline void write_udp_header(uint8_t* out, const UdpHeader& h) {
    out[0] = h.type;
    out[1] = h.service;
    out[2] = uint8_t(h.flow >> 24);
    out[3] = uint8_t(h.flow >> 16);
    out[4] = uint8_t(h.flow >> 8);
    out[5] = uint8_t(h.flow);
}

inline std::optional<UdpHeader> parse_udp_header(const std::vector<uint8_t>& pkt) {
    if (pkt.size() < UDP_HEADER_SIZE) return std::nullopt;
    return UdpHeader{pkt[0], pkt[1],
                     (uint32_t(pkt[2]) << 24) | (uint32_t(pkt[3]) << 16) |
                     (uint32_t(pkt[4]) << 8) | uint32_t(pkt[5])};
}

// --- Маршрутизируемый поток: заголовок открытым текстом для узлов на пути ---

inline constexpr std::size_t STREAM_HEADER_SIZE = 2 + 16 + 16;  // [версия][ttl][dst][src]
inline constexpr uint8_t STREAM_VERSION = 1;

struct StreamHeader {
    uint8_t ttl{0};
    NodeId dst{};
    NodeId src{};
};

inline std::vector<uint8_t> encode_stream_header(const StreamHeader& h) {
    std::vector<uint8_t> out{STREAM_VERSION, h.ttl};
    out.insert(out.end(), h.dst.begin(), h.dst.end());
    out.insert(out.end(), h.src.begin(), h.src.end());
    return out;
}

inline std::optional<StreamHeader> decode_stream_header(const uint8_t* data) {
    if (data[0] != STREAM_VERSION) return std::nullopt;
    StreamHeader h;
    h.ttl = data[1];
    std::memcpy(h.dst.data(), data + 2, 16);
    std::memcpy(h.src.data(), data + 18, 16);
    return h;
}

// Noise связывает рукопожатие с заголовком: подменить отправителя или получателя нельзя
inline std::vector<uint8_t> channel_prologue(const NodeId& initiator, const NodeId& responder) {
    constexpr char domain[] = "quokka-channel-v1";
    std::vector<uint8_t> out(domain, domain + sizeof(domain) - 1);
    out.insert(out.end(), initiator.begin(), initiator.end());
    out.insert(out.end(), responder.begin(), responder.end());
    return out;
}

// Запрос внутри третьего сообщения рукопожатия: промежуточные узлы его не видят
enum ChannelKind : uint8_t {
    CHANNEL_TCP = 1,  // [вид][сервис]
    CHANNEL_UDP = 2,  // [вид][сессия:4]
};

// --- Маяк поиска (шифруется целиком): "QBCN" + версия + QUIC-порт + идентификатор узла ---

inline constexpr char BEACON_MAGIC[] = "QBCN";
inline constexpr uint8_t BEACON_VERSION = 2;

struct Beacon {
    uint16_t quic_port{0};
    NodeId id{};
};

inline std::string encode_beacon(const Beacon& beacon) {
    std::string out(BEACON_MAGIC);
    out += static_cast<char>(BEACON_VERSION);
    out += static_cast<char>(beacon.quic_port >> 8);
    out += static_cast<char>(beacon.quic_port & 0xFF);
    out.append(reinterpret_cast<const char*>(beacon.id.data()), beacon.id.size());
    return out;
}

inline std::optional<Beacon> decode_beacon(const std::string& data) {
    constexpr std::size_t magic_size = sizeof(BEACON_MAGIC) - 1;
    if (data.size() != magic_size + 3 + 16 || data.compare(0, magic_size, BEACON_MAGIC) != 0 ||
        static_cast<uint8_t>(data[magic_size]) != BEACON_VERSION) {
        return std::nullopt;
    }
    Beacon beacon;
    beacon.quic_port = static_cast<uint16_t>((static_cast<uint8_t>(data[magic_size + 1]) << 8) |
                                             static_cast<uint8_t>(data[magic_size + 2]));
    if (beacon.quic_port == 0) return std::nullopt;
    std::memcpy(beacon.id.data(), data.data() + magic_size + 3, 16);
    return beacon;
}

}
