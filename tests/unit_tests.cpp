// Юнит-тесты без сети: код приглашения, ключи, Noise, карта сети, файлы секретов, разбор протокола.
#include "core/identity.hpp"
#include "core/noise.hpp"
#include "core/protocol.hpp"
#include "core/routing.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {

int g_failures = 0;

#define CHECK(condition)                                                                \
    do {                                                                                \
        if (!(condition)) {                                                             \
            std::cerr << __FILE__ << ":" << __LINE__ << ": FAILED: " #condition "\n";   \
            ++g_failures;                                                               \
        }                                                                               \
    } while (false)

template <class Fn>
bool throws(Fn&& fn) {
    try {
        fn();
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

identity::Invite sample_invite() {
    identity::Invite invite;
    for (std::size_t i = 0; i < invite.secret.size(); ++i) invite.secret[i] = uint8_t(200 - i);
    return invite;
}

void test_invite_round_trip() {
    const auto invite = sample_invite();
    const std::string code = identity::encode_invite(invite);
    CHECK(code.starts_with("quokka2"));

    const auto decoded = identity::decode_invite(code);
    CHECK(decoded && decoded->secret == invite.secret);

    // Код из мессенджера: верхний регистр, пробелы, перевод строки
    std::string messy;
    for (const char c : code) {
        messy += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (messy.size() % 10 == 0) messy += ' ';
    }
    CHECK(identity::decode_invite(messy + "\n").has_value());
}

void test_invite_rejects_damage() {
    const std::string code = identity::encode_invite(sample_invite());
    CHECK(!identity::decode_invite("").has_value());
    CHECK(!identity::decode_invite("quokka2").has_value());
    CHECK(!identity::decode_invite("quokka1abc").has_value());
    CHECK(!identity::decode_invite("hello world").has_value());
    CHECK(!identity::decode_invite(code.substr(0, code.size() - 1)).has_value());
    CHECK(!identity::decode_invite(code + "0").has_value());
    // Любая опечатка в любом символе ловится контрольной суммой
    for (std::size_t i = 7; i < code.size(); ++i) {
        std::string typo = code;
        typo[i] = typo[i] == '2' ? '3' : '2';
        CHECK(!identity::decode_invite(typo).has_value());
    }
}

void test_network_keys() {
    const auto invite = sample_invite();
    const auto a = identity::network_keys(invite);
    const auto b = identity::network_keys(invite);
    CHECK(a.discovery_key == b.discovery_key);
    CHECK(a.link_pin == b.link_pin);

    auto other = invite;
    other.secret[0] ^= 1;
    const auto c = identity::network_keys(other);
    CHECK(a.discovery_key != c.discovery_key);
    CHECK(a.link_pin != c.link_pin);
}

void test_certificate_pin_rejects_garbage() {
    const uint8_t garbage[] = {1, 2, 3, 4, 5};
    CHECK(!identity::pin_of_certificate(garbage, sizeof(garbage)).has_value());
    CHECK(!identity::pin_of_certificate(nullptr, 0).has_value());
}

void test_node_identity() {
    const auto node = identity::generate_identity();
    const auto other = identity::generate_identity();
    CHECK(node.id != other.id);
    CHECK(node.id == identity::node_id_of(node.signing_public));

    const uint8_t message[] = {1, 2, 3};
    auto signature = identity::sign(node, message, sizeof(message));
    CHECK(identity::verify(node.signing_public, message, sizeof(message), signature));
    CHECK(!identity::verify(other.signing_public, message, sizeof(message), signature));
    signature[0] ^= 1;
    CHECK(!identity::verify(node.signing_public, message, sizeof(message), signature));
}

void test_state_files() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("quokka-test-" + std::to_string(::getpid()));
    fs::remove_all(dir);

    const auto first = identity::load_or_create_identity(dir);
    const auto path = dir / "node.secret";
    struct stat st{};
    CHECK(::stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);

    // Личность узла переживает перезапуск
    const auto again = identity::load_or_create_identity(dir);
    CHECK(again.id == first.id && again.static_key.public_key == first.static_key.public_key);

    // Секрет, доступный другим пользователям, читать отказываемся
    ::chmod(path.c_str(), 0644);
    CHECK(throws([&] { identity::load_or_create_identity(dir); }));
    ::chmod(path.c_str(), 0600);

    { std::ofstream(path) << "quokka-node-v1\nnot-hex\nnot-hex\n"; }
    ::chmod(path.c_str(), 0600);
    CHECK(throws([&] { identity::load_or_create_identity(dir); }));

    // Символическая ссылка вместо файла не принимается
    fs::remove(path);
    fs::create_symlink("/etc/hosts", path);
    CHECK(throws([&] { identity::load_or_create_identity(dir); }));
    fs::remove(path);

    const auto invite = sample_invite();
    CHECK(!identity::load_saved_invite(dir).has_value());
    identity::save_invite(dir, invite);
    const auto saved = identity::load_saved_invite(dir);
    CHECK(saved && saved->secret == invite.secret);
    CHECK(::stat((dir / "network.invite").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);

    fs::remove_all(dir);
}

// --- Noise ---

struct NoiseParties {
    noise::KeyPair initiator_static = noise::generate_keypair();
    noise::KeyPair responder_static = noise::generate_keypair();
};

void test_noise_handshake() {
    NoiseParties p;
    const noise::Bytes prologue{1, 2, 3};
    noise::Handshake initiator(true, p.initiator_static, prologue);
    noise::Handshake responder(false, p.responder_static, prologue);

    const auto m1 = initiator.write_message({});
    CHECK(responder.read_message(m1.data(), m1.size()).has_value());
    const auto m2 = responder.write_message({});
    CHECK(initiator.read_message(m2.data(), m2.size()).has_value());
    CHECK(initiator.remote_static() == p.responder_static.public_key);

    const noise::Bytes request{9, 8, 7};
    const auto m3 = initiator.write_message(request);
    // Запрос не виден в открытом виде
    CHECK(std::search(m3.begin(), m3.end(), request.begin(), request.end()) == m3.end());
    const auto got = responder.read_message(m3.data(), m3.size());
    CHECK(got && *got == request);
    CHECK(responder.remote_static() == p.initiator_static.public_key);
    CHECK(initiator.finished() && responder.finished());

    const auto a = initiator.split();
    const auto b = responder.split();
    CHECK(a.stream_i2r == b.stream_i2r && a.stream_r2i == b.stream_r2i);
    CHECK(a.datagram_i2r == b.datagram_i2r && a.datagram_r2i == b.datagram_r2i);
    // Все четыре ключа разные
    CHECK(a.stream_i2r != a.stream_r2i && a.stream_i2r != a.datagram_i2r && a.datagram_i2r != a.datagram_r2i);

    // Каждое рукопожатие даёт новые ключи: прямая секретность
    noise::Handshake initiator2(true, p.initiator_static, prologue);
    noise::Handshake responder2(false, p.responder_static, prologue);
    const auto x1 = initiator2.write_message({});
    responder2.read_message(x1.data(), x1.size());
    const auto x2 = responder2.write_message({});
    initiator2.read_message(x2.data(), x2.size());
    const auto x3 = initiator2.write_message({});
    responder2.read_message(x3.data(), x3.size());
    CHECK(initiator2.split().stream_i2r != a.stream_i2r);
}

void test_noise_rejects_tampering() {
    NoiseParties p;
    // Любой изменённый байт второго сообщения ломает рукопожатие
    for (const std::size_t position : {std::size_t{0}, std::size_t{40}, std::size_t{70}, std::size_t{95}}) {
        noise::Handshake initiator(true, p.initiator_static, {});
        noise::Handshake responder(false, p.responder_static, {});
        const auto m1 = initiator.write_message({});
        responder.read_message(m1.data(), m1.size());
        auto m2 = responder.write_message({});
        m2[position] ^= 1;
        CHECK(!initiator.read_message(m2.data(), m2.size()).has_value());
    }
    // Третье сообщение тоже
    {
        noise::Handshake initiator(true, p.initiator_static, {});
        noise::Handshake responder(false, p.responder_static, {});
        const auto m1 = initiator.write_message({});
        responder.read_message(m1.data(), m1.size());
        const auto m2 = responder.write_message({});
        initiator.read_message(m2.data(), m2.size());
        auto m3 = initiator.write_message({1});
        m3[5] ^= 1;
        CHECK(!responder.read_message(m3.data(), m3.size()).has_value());
    }
    // Разный пролог (подменённые отправитель или получатель в заголовке) ломает рукопожатие
    {
        noise::Handshake initiator(true, p.initiator_static, {1});
        noise::Handshake responder(false, p.responder_static, {2});
        const auto m1 = initiator.write_message({});
        responder.read_message(m1.data(), m1.size());
        const auto m2 = responder.write_message({});
        CHECK(!initiator.read_message(m2.data(), m2.size()).has_value());
    }
    // Обрезанное сообщение и ключ малого порядка
    {
        noise::Handshake responder(false, p.responder_static, {});
        const uint8_t short_message[10]{};
        CHECK(!responder.read_message(short_message, sizeof(short_message)).has_value());

        noise::Handshake initiator(true, p.initiator_static, {});
        initiator.write_message({});
        const std::array<uint8_t, 96> zero_key{};
        CHECK(!initiator.read_message(zero_key.data(), zero_key.size()).has_value());
    }
}

void test_seal_open() {
    noise::Key key{};
    key[0] = 1;
    const uint8_t aad[] = {5, 6};
    const noise::Bytes plain{1, 2, 3, 4};
    auto cipher = noise::seal(key, 7, aad, sizeof(aad), plain.data(), plain.size());
    const auto opened = noise::open(key, 7, aad, sizeof(aad), cipher.data(), cipher.size());
    CHECK(opened && *opened == plain);

    CHECK(!noise::open(key, 8, aad, sizeof(aad), cipher.data(), cipher.size()).has_value());
    const uint8_t other_aad[] = {5, 7};
    CHECK(!noise::open(key, 7, other_aad, sizeof(other_aad), cipher.data(), cipher.size()).has_value());
    cipher[0] ^= 1;
    CHECK(!noise::open(key, 7, aad, sizeof(aad), cipher.data(), cipher.size()).has_value());

    const auto empty = noise::seal(key, 1, nullptr, 0, nullptr, 0);
    const auto opened_empty = noise::open(key, 1, nullptr, 0, empty.data(), empty.size());
    CHECK(opened_empty && opened_empty->empty());
}

void test_replay_window() {
    noise::ReplayWindow window;
    CHECK(window.accept(0));
    CHECK(!window.accept(0));
    CHECK(window.accept(5));
    CHECK(window.accept(3));       // пришёл с опозданием: можно
    CHECK(!window.accept(3));      // повтор: нельзя
    CHECK(window.accept(10000));
    CHECK(!window.accept(5));      // за пределами окна
    CHECK(window.accept(9000));
    CHECK(!window.accept(9000));
    for (uint64_t i = 10001; i < 10100; ++i) CHECK(window.accept(i));
    CHECK(!window.accept(10050));
    // Сдвиг окна очищает старые биты: новый счётчик в той же ячейке проходит
    CHECK(window.accept(10000 + 2048));
    CHECK(!window.accept(10000 + 2048));
}

// --- Карта сети ---

struct TestNode {
    identity::NodeIdentity identity = identity::generate_identity();

    std::vector<uint8_t> encode(uint64_t sequence, std::vector<identity::NodeId> neighbors) const {
        routing::NodeInfo info;
        info.signing_key = identity.signing_public;
        info.static_key = identity.static_key.public_key;
        info.sequence = sequence;
        info.neighbors = std::move(neighbors);
        return routing::encode_node_info(info, identity);
    }
};

void test_node_info_signature() {
    TestNode node;
    routing::NodeInfo info;
    info.signing_key = node.identity.signing_public;
    info.static_key = node.identity.static_key.public_key;
    info.sequence = 42;
    info.name = "alice";
    info.services = {{ServiceProto::Tcp, 8000}, {ServiceProto::Udp, 27015}};
    const auto encoded = routing::encode_node_info(info, node.identity);

    const auto decoded = routing::decode_node_info(encoded.data(), encoded.size());
    CHECK(decoded && decoded->name == "alice" && decoded->services == info.services && decoded->sequence == 42);
    CHECK(decoded && decoded->id() == node.identity.id);

    // Изменение любого байта обнаруживается
    for (std::size_t i = 0; i < encoded.size(); i += 7) {
        auto forged = encoded;
        forged[i] ^= 1;
        CHECK(!routing::decode_node_info(forged.data(), forged.size()).has_value());
    }

    // Участник не может выпустить сведения от имени другого узла: подпись его собственная
    TestNode attacker;
    routing::NodeInfo stolen = info;
    const auto forged = routing::encode_node_info(stolen, attacker.identity);
    CHECK(!routing::decode_node_info(forged.data(), forged.size()).has_value());

    CHECK(!routing::decode_node_info(encoded.data(), encoded.size() - 1).has_value());
    CHECK(!routing::decode_node_info(encoded.data(), 10).has_value());

    // Управляющие символы в имени могли бы подделывать строки лога
    routing::NodeInfo bad_name = info;
    bad_name.name = "a\nb";
    const auto with_newline = routing::encode_node_info(bad_name, node.identity);
    CHECK(!routing::decode_node_info(with_newline.data(), with_newline.size()).has_value());
    CHECK(routing::is_valid_name("Вася 1"));
    CHECK(!routing::is_valid_name("a\033[2J"));
}

void test_database_updates() {
    using Result = routing::Database::InsertResult;
    TestNode self, other;
    routing::Database db(self.identity.id);
    auto now = routing::Database::Clock::now();

    const auto v2 = other.encode(2, {});
    CHECK(db.insert(v2.data(), v2.size(), now) == Result::Updated);
    CHECK(db.insert(v2.data(), v2.size(), now) == Result::Stale);

    // Старые сведения не вытесняют новые: иначе атакующий мог бы вернуть прошлое состояние
    const auto v1 = other.encode(1, {});
    CHECK(db.insert(v1.data(), v1.size(), now) == Result::Stale);

    // Слишком частое обновление не теряется, а откладывается: иначе узел надолго остался бы без соседа
    const auto v3 = other.encode(3, {self.identity.id});
    CHECK(db.insert(v3.data(), v3.size(), now) == Result::Throttled);
    CHECK(db.find(other.identity.id)->sequence == 2);
    CHECK(db.apply_deferred(now).empty());
    const auto v4 = other.encode(4, {self.identity.id});
    CHECK(db.insert(v4.data(), v4.size(), now) == Result::Throttled);
    now += std::chrono::seconds(1);
    const auto applied = db.apply_deferred(now);
    CHECK(applied.size() == 1 && applied[0] == v4);  // из очереди берётся самое новое
    CHECK(db.find(other.identity.id)->sequence == 4);
    CHECK(db.apply_deferred(now).empty());
    now += std::chrono::seconds(1);
    const auto v5 = other.encode(5, {});
    CHECK(db.insert(v5.data(), v5.size(), now) == Result::Updated);

    // Сведения о самом себе извне не принимаются
    const auto about_self = self.encode(999, {});
    CHECK(db.insert(about_self.data(), about_self.size(), now) == Result::Stale);

    auto garbage = v3;
    garbage[3] ^= 1;
    CHECK(db.insert(garbage.data(), garbage.size(), now) == Result::Invalid);

    CHECK(db.expire(now + std::chrono::seconds(10)).empty());
    const auto removed = db.expire(now + routing::Database::EXPIRY + std::chrono::seconds(1));
    CHECK(removed.size() == 1 && removed[0] == other.identity.id);
    CHECK(db.find(other.identity.id) == nullptr);
}

void test_routes() {
    // self - a - b - c, плюс обход self - d - c
    TestNode self, a, b, c, d;
    const auto ida = a.identity.id, idb = b.identity.id, idc = c.identity.id, idd = d.identity.id;
    const auto ids = self.identity.id;
    routing::Database db(ids);
    const auto now = routing::Database::Clock::now();
    const auto add = [&](const TestNode& node, std::vector<identity::NodeId> neighbors) {
        const auto encoded = node.encode(1, std::move(neighbors));
        CHECK(db.insert(encoded.data(), encoded.size(), now) == routing::Database::InsertResult::Updated);
    };
    add(a, {ids, idb});
    add(b, {ida, idc});
    add(c, {idb});

    auto routes = db.compute_routes({ida});
    CHECK(routes[ida].hops == 1);
    CHECK(routes[idb].hops == 2 && routes[idb].next_hop == ida);
    CHECK(routes[idc].hops == 3 && routes[idc].next_hop == ida);

    // Связь считается, только если о ней сообщили оба конца
    routing::Database one_sided(ids);
    const auto a_only = a.encode(1, {ids, idb});
    const auto b_silent = b.encode(1, {});
    one_sided.insert(a_only.data(), a_only.size(), now);
    one_sided.insert(b_silent.data(), b_silent.size(), now);
    CHECK(!one_sided.compute_routes({ida}).contains(idb));

    // Узел без сведений о себе недостижим, сколько бы о нём ни рассказывали
    routing::Database unknown(ids);
    unknown.insert(a_only.data(), a_only.size(), now);
    CHECK(!unknown.compute_routes({ida}).contains(idb));

    // Короткий обход предпочитается длинному пути
    routing::Database with_bypass(ids);
    const auto insert = [&](const TestNode& node, std::vector<identity::NodeId> neighbors) {
        const auto encoded = node.encode(1, std::move(neighbors));
        with_bypass.insert(encoded.data(), encoded.size(), now);
    };
    insert(a, {ids, idb});
    insert(b, {ida, idc});
    insert(c, {idb, idd});
    insert(d, {ids, idc});
    routes = with_bypass.compute_routes({ida, idd});
    CHECK(routes[idc].hops == 2 && routes[idc].next_hop == idd);

    // Сосед пропал: маршрут идёт в обход
    routes = with_bypass.compute_routes({ida});
    CHECK(routes[idc].hops == 3 && routes[idc].next_hop == ida);
    routes = with_bypass.compute_routes({});
    CHECK(routes.empty());

    // Цикл в карте не вешает расчёт
    routing::Database cycle(ids);
    const auto c1 = a.encode(1, {ids, idb});
    const auto c2 = b.encode(1, {ida, idc});
    const auto c3 = c.encode(1, {idb, ida});
    cycle.insert(c1.data(), c1.size(), now);
    cycle.insert(c2.data(), c2.size(), now);
    cycle.insert(c3.data(), c3.size(), now);
    CHECK(cycle.compute_routes({ida}).size() == 3);
}

// --- Протокол ---

void test_routed_header() {
    protocol::RoutedHeader h;
    h.ttl = 7;
    h.dst[0] = 1;
    h.src[15] = 2;
    h.from_initiator = 1;
    h.session = 0xA1B2C3D4;
    std::vector<uint8_t> pkt(protocol::ROUTED_HEADER_SIZE + protocol::DG_COUNTER_SIZE);
    protocol::write_routed_header(pkt.data(), h);
    const auto parsed = protocol::parse_routed_header(pkt);
    CHECK(parsed && parsed->ttl == 7 && parsed->dst == h.dst && parsed->src == h.src &&
          parsed->from_initiator == 1 && parsed->session == 0xA1B2C3D4);

    pkt.resize(protocol::ROUTED_HEADER_SIZE);
    CHECK(!protocol::parse_routed_header(pkt).has_value());
    CHECK(!protocol::parse_routed_header({}).has_value());
}

void test_stream_header() {
    protocol::StreamHeader h;
    h.ttl = 3;
    h.dst[1] = 9;
    h.src[2] = 8;
    auto encoded = protocol::encode_stream_header(h);
    CHECK(encoded.size() == protocol::STREAM_HEADER_SIZE);
    const auto decoded = protocol::decode_stream_header(encoded.data());
    CHECK(decoded && decoded->ttl == 3 && decoded->dst == h.dst && decoded->src == h.src);
    encoded[0] = 99;
    CHECK(!protocol::decode_stream_header(encoded.data()).has_value());
}

void test_udp_header() {
    std::vector<uint8_t> pkt(protocol::UDP_HEADER_SIZE);
    protocol::write_udp_header(pkt.data(), {protocol::UDP_REPLY, 5, 0xA1B2C3D4});
    const auto header = protocol::parse_udp_header(pkt);
    CHECK(header && header->type == protocol::UDP_REPLY && header->service == 5 && header->flow == 0xA1B2C3D4);
    pkt.pop_back();
    CHECK(!protocol::parse_udp_header(pkt).has_value());
}

void test_beacon() {
    protocol::Beacon beacon{30002, {}};
    beacon.id[3] = 7;
    const auto decoded = protocol::decode_beacon(protocol::encode_beacon(beacon));
    CHECK(decoded && decoded->quic_port == 30002 && decoded->id == beacon.id);
    CHECK(!protocol::decode_beacon("").has_value());
    CHECK(!protocol::decode_beacon("QBCN").has_value());
    CHECK(!protocol::decode_beacon(protocol::encode_beacon(beacon) + "x").has_value());

    Aead::Key key{};
    key[0] = 1;
    Aead good(key);
    key[0] = 2;
    Aead bad(key);
    auto packet = good.encrypt(protocol::encode_beacon(beacon));
    std::string plain;
    CHECK(good.decrypt(packet.data(), packet.size(), plain));
    CHECK(!bad.decrypt(packet.data(), packet.size(), plain));
    packet.back() ^= 1;
    CHECK(!good.decrypt(packet.data(), packet.size(), plain));
}

}

int main() {
    test_invite_round_trip();
    test_invite_rejects_damage();
    test_network_keys();
    test_certificate_pin_rejects_garbage();
    test_node_identity();
    test_state_files();
    test_noise_handshake();
    test_noise_rejects_tampering();
    test_seal_open();
    test_replay_window();
    test_node_info_signature();
    test_database_updates();
    test_routes();
    test_routed_header();
    test_stream_header();
    test_udp_header();
    test_beacon();

    if (g_failures == 0) std::cout << "OK\n";
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
