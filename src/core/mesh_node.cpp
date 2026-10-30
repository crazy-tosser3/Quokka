#include "core/mesh_node.hpp"

#include "core/log.hpp"
#include "core/quic_runtime.hpp"
#include "core/tcp_bridge.hpp"

#include <boost/asio/post.hpp>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace {

constexpr auto DIAL_RETRY = std::chrono::seconds(3);
constexpr auto DIAL_RETRY_FULL = std::chrono::seconds(10);
constexpr auto LOWER_ID_GRACE = std::chrono::seconds(10);
constexpr auto BEACON_FORGET = std::chrono::seconds(30);
constexpr auto HELLO_TIMEOUT = std::chrono::seconds(10);
constexpr auto REFRESH_INTERVAL = std::chrono::seconds(30);
constexpr auto ORIGINATE_DELAY = std::chrono::milliseconds(200);
constexpr auto RECOMPUTE_DELAY = std::chrono::milliseconds(50);
constexpr auto HEADER_TIMEOUT = std::chrono::seconds(10);
// Соседу раз в секунду идёт пинг, поэтому такая тишина означает, что он пропал.
// Ждать таймаута QUIC в 15 секунд нельзя: игра всё это время будет стоять.
constexpr auto LINK_SILENCE_LIMIT = std::chrono::seconds(4);
constexpr std::size_t MAX_PENDING_DATAGRAMS = 32;
constexpr std::size_t MAX_SESSIONS_PER_PEER = 16;

int64_t now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

uint64_t now_ms_wall() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

template <class T>
void fill_random(T& out) {
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&out), sizeof(out)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
}

}

// Читает открытый заголовок маршрутизируемого потока
class MeshNode::StreamHeaderReader : public QuicByteStream::Handler,
                                     public std::enable_shared_from_this<StreamHeaderReader> {
public:
    StreamHeaderReader(MeshNode& node, QuicByteStream::Ref stream)
        : node_(node), stream_(std::move(stream)), timer_(node.io_) {}

    void start() {
        timer_.expires_after(HEADER_TIMEOUT);
        timer_.async_wait([weak = weak_from_this()](boost::system::error_code ec) {
            const auto self = weak.lock();
            if (!ec && self && self->stream_) self->stream_->abort();
        });
    }

    void on_stream_data(std::vector<uint8_t>&& data) override {
        if (!stream_) return;
        buffer_.insert(buffer_.end(), data.begin(), data.end());
        if (buffer_.size() < protocol::STREAM_HEADER_SIZE) return;

        const auto header = protocol::decode_stream_header(buffer_.data());
        auto stream = std::move(stream_);
        timer_.cancel();
        if (!header) {
            stream->abort();
            return;
        }
        stream->consumed(protocol::STREAM_HEADER_SIZE);
        std::vector<uint8_t> rest(buffer_.begin() + protocol::STREAM_HEADER_SIZE, buffer_.end());
        node_.on_stream_header(stream, *header, std::move(rest));
    }
    void on_stream_fin() override { if (stream_) stream_->abort(); }
    void on_stream_closed() override { stream_.reset(); timer_.cancel(); }

private:
    MeshNode& node_;
    QuicByteStream::Ref stream_;
    boost::asio::steady_timer timer_;
    std::vector<uint8_t> buffer_;
};

namespace {

// Транзитный поток: байты идут дальше без расшифровки, с обратным давлением в обе стороны
class StreamRelay : public std::enable_shared_from_this<StreamRelay> {
public:
    StreamRelay(Stats& stats, QuicByteStream::Ref a, QuicByteStream::Ref b, std::function<void(const uint8_t*, std::size_t)> tap)
        : stats_(stats), streams_{std::move(a), std::move(b)}, tap_(std::move(tap)) {
        ++stats_.relayed_streams;
    }
#ifdef QUOKKA_TEST_HOOKS
    std::size_t evil_truncate{0};
    std::size_t evil_forwarded{0};
#endif
    ~StreamRelay() { --stats_.relayed_streams; }

    class Side : public QuicByteStream::Handler {
    public:
        Side(std::shared_ptr<StreamRelay> relay, int index) : relay_(std::move(relay)), index_(index) {}
        void on_stream_data(std::vector<uint8_t>&& data) override { relay_->on_data(index_, data); }
        void on_stream_fin() override { relay_->on_fin(index_); }
        void on_stream_closed() override { relay_->on_closed(index_); }
        void on_stream_writable() override { relay_->on_writable(index_); }
    private:
        std::shared_ptr<StreamRelay> relay_;
        int index_;
    };

    void start(std::vector<uint8_t>&& first) {
        streams_[0]->set_handler(std::make_shared<Side>(shared_from_this(), 0));
        streams_[1]->set_handler(std::make_shared<Side>(shared_from_this(), 1));
        if (!first.empty()) on_data(0, first);
    }

private:
    void on_data(int from, const std::vector<uint8_t>& data) {
        if (tap_) tap_(data.data(), data.size());
        auto& source = streams_[from];
        auto& sink = streams_[1 - from];
#ifdef QUOKKA_TEST_HOOKS
        // Атака: обрезать ответ и выдать это за штатный конец данных
        if (evil_truncate > 0 && from == 1 && sink && (evil_forwarded += data.size()) > evil_truncate) {
            sink->finish();
            return;
        }
#endif
        if (!source || !sink || !sink->send(data.data(), data.size())) {
            abort_all();
            return;
        }
        // Пока следующий узел не успевает, приём держим неподтверждённым: окно QUIC закроется само
        if (sink->congested()) pending_[from] += data.size();
        else source->consumed(data.size());
    }
    void on_writable(int side) {
        const int blocked = 1 - side;
        if (streams_[blocked] && pending_[blocked] > 0) {
            streams_[blocked]->consumed(pending_[blocked]);
            pending_[blocked] = 0;
        }
    }
    void on_fin(int from) {
        fin_from_[from] = true;
        if (auto& sink = streams_[1 - from]) sink->finish();
    }
    void on_closed(int side) {
        streams_[side].reset();
        // Штатно завершённая сторона не повод рвать вторую: там ещё могут идти последние данные.
        // Вторая завершится сама, когда их подтвердят.
        const bool graceful = fin_from_[0] && fin_from_[1];
        if (auto& other = streams_[1 - side]; other && !graceful) other->abort();
    }
    void abort_all() {
        for (auto& stream : streams_) if (stream) stream->abort();
    }

    Stats& stats_;
    std::array<QuicByteStream::Ref, 2> streams_;
    std::array<std::size_t, 2> pending_{0, 0};
    std::array<bool, 2> fin_from_{false, false};
    std::function<void(const uint8_t*, std::size_t)> tap_;
};

}

MeshNode::MeshNode(boost::asio::io_context& io, const NodeConfig& config, Stats& stats,
                   const identity::NetworkKeys& keys, const identity::NodeIdentity& self)
    : io_(io),
      config_(config),
      stats_(stats),
      self_(self),
      sessions_{io, *this, keys.link_pin},
      db_(self.id),
      originate_timer_(io),
      recompute_timer_(io),
      tick_timer_(io),
      started_at_(Clock::now())
{
#ifdef QUOKKA_TEST_HOOKS
    if (const char* tap = std::getenv("QUOKKA_EVIL_TAP")) evil_tap_ = tap;
    evil_terminate_ = std::getenv("QUOKKA_EVIL_TERMINATE") != nullptr;
    if (const char* service = std::getenv("QUOKKA_EVIL_SERVICE")) evil_service_ = std::atoi(service);
    if (const char* truncate = std::getenv("QUOKKA_EVIL_TRUNCATE")) evil_truncate_ = static_cast<std::size_t>(std::atoll(truncate));
#endif

    start_listener();

    const auto now = Clock::now();
    for (const PeerAddress& peer : config_.peers) {
        DialTarget target;
        target.host = peer.host;
        target.port = peer.port;
        target.configured = true;
        target.first_seen = now;
        target.last_seen = now;
        target.retry_after = now;
        targets_[peer.host + ":" + std::to_string(peer.port)] = target;
    }

    if (config_.discovery) {
        protocol::Beacon beacon{quic_port_, self_.id};
        beacon_sender_.emplace(io_, config_.multicast_ip, config_.discovery_port, beacon, keys.discovery_key);
        beacon_receiver_.emplace(io_, config_.multicast_ip, config_.discovery_port, keys.discovery_key,
            [this](const boost::asio::ip::address& address, const protocol::Beacon& found) {
                on_beacon(address, found);
            });
    }

    originate();
    do_tick();
}

MeshNode::~MeshNode() {
    stopping_ = true;
    if (quic_listener_) quic::api->ListenerClose(quic_listener_);
    drain_sessions(io_, sessions_.open_sessions);
}

NodeStatus MeshNode::status() const {
    NodeStatus s;
    s.id = identity::short_id(self_.id);
    s.quic_port = quic_port_;
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        s.peers = peer_status_;
    }
    s.tcp_bridges = stats_.tcp_bridges.load();
    s.udp_flows = stats_.udp_flows.load();
    s.udp_packets_sent = stats_.udp_packets_sent.load();
    s.udp_packets_received = stats_.udp_packets_received.load();
    s.udp_packets_dropped = stats_.udp_packets_dropped.load();
    s.relayed_datagrams = stats_.relayed_datagrams.load();
    s.relayed_streams = stats_.relayed_streams.load();
    return s;
}

// --- Соединения с соседями ---

void MeshNode::start_listener() {
    if (QUIC_FAILED(quic::api->ListenerOpen(quic::registration, MeshNode::listener_callback, this, &quic_listener_))) {
        throw std::runtime_error("Не удалось создать QUIC-listener");
    }
    const auto start_on = [this](uint16_t port) {
        QUIC_ADDR addr{};
        QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_INET);
        QuicAddrSetPort(&addr, port);
        return QUIC_SUCCEEDED(quic::api->ListenerStart(quic_listener_, &quic::alpn(), 1, &addr));
    };
    if (!start_on(config_.quic_port)) {
        // На одной машине может работать несколько узлов: порт сообщается в маяке
        if (config_.quic_port_explicit || !start_on(0)) {
            quic::api->ListenerClose(quic_listener_);
            quic_listener_ = nullptr;
            throw std::runtime_error("Порт " + std::to_string(config_.quic_port) +
                                     "/udp занят. Укажите другой: --port <порт>");
        }
    }
    QUIC_ADDR actual{};
    uint32_t size = sizeof(actual);
    if (QUIC_FAILED(quic::api->GetParam(quic_listener_, QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &size, &actual))) {
        throw std::runtime_error("Не удалось узнать QUIC-порт");
    }
    quic_port_ = QuicAddrGetPort(&actual);
}

QUIC_STATUS QUIC_API MeshNode::listener_callback(HQUIC, void* context, QUIC_LISTENER_EVENT* event) {
    auto* node = static_cast<MeshNode*>(context);
    if (event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        return QuicSession::accept(node->sessions_, event->NEW_CONNECTION.Connection);
    }
    return QUIC_STATUS_NOT_SUPPORTED;
}

void MeshNode::on_beacon(const boost::asio::ip::address& address, const protocol::Beacon& beacon) {
    if (beacon.id == self_.id) return;
    const std::string key = address.to_string() + ":" + std::to_string(beacon.quic_port);
    const auto now = Clock::now();
    auto [it, inserted] = targets_.try_emplace(key);
    DialTarget& target = it->second;
    if (inserted) {
        target.host = address.to_string();
        target.port = beacon.quic_port;
        target.first_seen = now;
        target.retry_after = now;
    }
    target.last_seen = now;
    if (!target.configured) target.id = beacon.id;
}

void MeshNode::dial(const std::string& key, DialTarget& target) {
    target.in_progress = true;
    target.retry_after = Clock::now() + DIAL_RETRY;
    try {
        logging::debug("[Сеть] Подключаюсь к ", key);
        const auto session = QuicSession::connect(sessions_, target.host, target.port);
        pending_dials_[session.get()] = key;
    } catch (const std::exception& e) {
        target.in_progress = false;
        logging::debug("[Сеть] ", key, ": ", e.what());
    }
}

void MeshNode::do_tick() {
    const auto now = Clock::now();

    std::set<NodeId> dialing;
    for (const auto& [key, target] : targets_) {
        if (target.in_progress && target.id) dialing.insert(*target.id);
    }

    for (auto it = targets_.begin(); it != targets_.end();) {
        DialTarget& target = it->second;
        if (!target.configured && !target.in_progress && now - target.last_seen > BEACON_FORGET) {
            it = targets_.erase(it);
            continue;
        }
        const bool have_link = target.id && (links_by_id_.contains(*target.id) || *target.id == self_.id);
        const bool someone_else = target.id && dialing.contains(*target.id);
        // Чтобы не создавать встречных соединений, первым подключается меньший идентификатор.
        // Если сосед не смог (файрвол в одну сторону), подключаемся сами: лишнее соединение закроется.
        const bool wait_for_peer = !target.configured && target.id && self_.id > *target.id &&
                                   now - target.first_seen < LOWER_ID_GRACE;
        if (!target.in_progress && !have_link && !someone_else && !wait_for_peer && now >= target.retry_after) {
            if (target.id) dialing.insert(*target.id);
            dial(it->first, target);
        }
        ++it;
    }

    // Сосед не представился вовремя
    for (const auto& [session, link] : links_) {
        if (!link->id && now - link->opened_at > HELLO_TIMEOUT) link->session->shutdown(protocol::CLOSE_PROTOCOL_ERROR);
    }

    for (const auto& [id, link] : links_by_id_) check_link_alive(link, now);

    const auto deferred = db_.apply_deferred(now);
    for (const auto& encoded : deferred) flood(encoded, nullptr);
    if (!deferred.empty()) schedule_recompute();

    if (now - last_originate_ >= REFRESH_INTERVAL) schedule_originate();

    const auto removed = db_.expire(now);
    if (!removed.empty()) schedule_recompute();

    if (!lonely_hint_shown_ && routes_.empty() && now - started_at_ > std::chrono::seconds(20)) {
        lonely_hint_shown_ = true;
        logging::warn("Других узлов пока не видно. Проверьте, что они запущены с тем же кодом и в одной сети.\n"
                      "Если сеть блокирует автопоиск, укажите адрес соседа: --peer <IP>[:порт]");
    }

    {
        std::vector<PeerStatus> peers;
        for (const auto& [id, route] : routes_) {
            PeerStatus peer;
            peer.id = identity::short_id(id);
            if (const auto* info = db_.find(id)) peer.name = info->name;
            peer.hops = route.hops;
            if (route.hops == 1) {
                const auto link = links_by_id_.find(id);
                if (link != links_by_id_.end() && link->second->rtt_us.load() >= 0) {
                    peer.rtt_ms = link->second->rtt_us.load() / 1000.0;
                }
            }
            peers.push_back(std::move(peer));
        }
        std::lock_guard<std::mutex> lock(status_mutex_);
        peer_status_ = std::move(peers);
    }

    // Пинг по тому же пути, что и трафик, показывает реальную задержку
    const int64_t ts = now_us();
    std::vector<uint8_t> ping(1 + sizeof(ts));
    ping[0] = protocol::DG_PING;
    std::memcpy(ping.data() + 1, &ts, sizeof(ts));
    for (const auto& [id, link] : links_by_id_) {
        auto copy = ping;
        link->session->send_datagram(std::move(copy));
    }

    tick_timer_.expires_after(std::chrono::seconds(1));
    tick_timer_.async_wait([this](boost::system::error_code ec) {
        if (!ec && !stopping_) do_tick();
    });
}

// Считаем все пакеты соединения, а не только ответы на пинг: при сильной загрузке
// датаграммы могут теряться, хотя сосед жив и данные идут.
void MeshNode::check_link_alive(const std::shared_ptr<Link>& link, Clock::time_point now) {
    QUIC_STATISTICS_V2 stats{};
    uint32_t size = sizeof(stats);
    if (QUIC_FAILED(quic::api->GetParam(link->session->handle(), QUIC_PARAM_CONN_STATISTICS_V2, &size, &stats))) return;
    if (stats.RecvTotalPackets != link->received_packets) {
        link->received_packets = stats.RecvTotalPackets;
        link->last_heard = now;
        return;
    }
    if (link->usable && now - link->last_heard > LINK_SILENCE_LIMIT) {
        logging::info("[Сеть] Сосед ", identity::short_id(*link->id), " не отвечает, ищу другой маршрут");
        link->usable = false;
        link->session->abandon();
        schedule_originate();
        schedule_recompute();
    }
}

void MeshNode::on_session_ready(const QuicSession::Ref& session) {
    auto link = std::make_shared<Link>();
    link->session = session;
    link->opened_at = Clock::now();
    fill_random(link->my_nonce);
    if (const auto dial_it = pending_dials_.find(session.get()); dial_it != pending_dials_.end()) {
        link->dialer = true;
        link->dial_key = dial_it->second;
    }
    links_[session.get()] = link;

    link->control_out = QuicByteStream::open(io_, session->handle(), true);
    if (!link->control_out) {
        session->shutdown(protocol::CLOSE_PROTOCOL_ERROR);
        return;
    }
    struct Silent : QuicByteStream::Handler {
        void on_stream_data(std::vector<uint8_t>&&) override {}
        void on_stream_fin() override {}
        void on_stream_closed() override {}
    };
    link->control_out->set_handler(std::make_shared<Silent>());
    send_control(link, protocol::CTRL_CHALLENGE, link->my_nonce.data(), link->my_nonce.size());
}

bool MeshNode::on_peer_stream(const QuicSession::Ref& session, HQUIC stream, bool unidirectional) {
    if (!unidirectional && !session->admitted()) return false;  // сосед ещё не представился
    auto accepted = QuicByteStream::accept(io_, stream);
    boost::asio::post(io_, [this, session, accepted, unidirectional] {
        const auto it = links_.find(session.get());
        if (it == links_.end()) {
            accepted->set_handler(nullptr);
            accepted->abort();
            return;
        }
        if (unidirectional) on_control_stream(it->second, accepted);
        else on_routed_stream(accepted);
    });
    return true;
}

void MeshNode::send_control(const std::shared_ptr<Link>& link, protocol::ControlType type,
                            const uint8_t* body, std::size_t size) {
    if (!link->control_out) return;
    const auto frame = protocol::make_control_frame(type, body, size);
    link->control_out->send(frame.data(), frame.size());
}

void MeshNode::on_control_stream(const std::shared_ptr<Link>& link, const QuicByteStream::Ref& stream) {
    if (link->control_in) {
        stream->abort();
        return;
    }
    link->control_in = stream;

    class Reader : public QuicByteStream::Handler {
    public:
        Reader(MeshNode& node, std::shared_ptr<Link> link) : node_(node), link_(std::move(link)) {}
        void on_stream_data(std::vector<uint8_t>&& data) override { node_.on_control_data(link_, std::move(data)); }
        void on_stream_fin() override { link_->session->shutdown(protocol::CLOSE_PROTOCOL_ERROR); }
        void on_stream_closed() override {}
    private:
        MeshNode& node_;
        std::shared_ptr<Link> link_;
    };
    stream->set_handler(std::make_shared<Reader>(*this, link));
}

void MeshNode::on_control_data(const std::shared_ptr<Link>& link, std::vector<uint8_t>&& data) {
    const std::size_t received = data.size();
    link->control_rx.insert(link->control_rx.end(), data.begin(), data.end());
    if (link->control_in) link->control_in->consumed(received);

    std::size_t offset = 0;
    auto& rx = link->control_rx;
    while (rx.size() - offset >= 3) {
        const std::size_t size = (std::size_t(rx[offset]) << 8) | rx[offset + 1];
        if (size == 0 || size > protocol::MAX_CONTROL_FRAME) {
            link->session->shutdown(protocol::CLOSE_PROTOCOL_ERROR);
            rx.clear();
            return;
        }
        if (rx.size() - offset < 2 + size) break;
        if (!handle_control_frame(link, rx[offset + 2], rx.data() + offset + 3, size - 1)) {
            link->session->shutdown(protocol::CLOSE_PROTOCOL_ERROR);
            rx.clear();
            return;
        }
        offset += 2 + size;
    }
    rx.erase(rx.begin(), rx.begin() + static_cast<std::ptrdiff_t>(offset));
}

bool MeshNode::handle_control_frame(const std::shared_ptr<Link>& link, uint8_t type, const uint8_t* body, std::size_t size) {
    switch (type) {
    case protocol::CTRL_CHALLENGE: {
        if (link->peer_nonce || size != sizeof(Nonce)) return false;
        Nonce nonce;
        std::copy_n(body, nonce.size(), nonce.begin());
        link->peer_nonce = nonce;
        // Подпись показывает, что мы владеем своим ключом, причём именно сейчас
        const auto message = protocol::hello_signed_data(nonce, link->my_nonce);
        const auto signature = identity::sign(self_, message.data(), message.size());
        std::vector<uint8_t> hello(self_.signing_public.begin(), self_.signing_public.end());
        hello.insert(hello.end(), signature.begin(), signature.end());
        send_control(link, protocol::CTRL_HELLO, hello.data(), hello.size());
        return true;
    }
    case protocol::CTRL_HELLO:
        return handle_hello(link, body, size);
    case protocol::CTRL_READY: {
        if (!link->id || link->usable) return false;
        link->usable = true;
        logging::debug("[Сеть] Сосед готов: ", identity::short_id(*link->id));
        schedule_originate();
        schedule_recompute();
        return true;
    }
    case protocol::CTRL_NODE_INFO: {
        if (!link->id) return false;
        const auto result = db_.insert(body, size, Clock::now());
        if (result == routing::Database::InsertResult::Updated) {
            flood(std::vector<uint8_t>(body, body + size), link.get());
            schedule_recompute();
        } else if (result == routing::Database::InsertResult::Invalid) {
            logging::warn("[Безопасность] Сосед ", identity::short_id(*link->id), " прислал сведения с неверной подписью");
        }
        return true;
    }
    default:
        return true;  // неизвестные кадры пропускаем: так новые версии смогут добавлять свои
    }
}

bool MeshNode::handle_hello(const std::shared_ptr<Link>& link, const uint8_t* body, std::size_t size) {
    if (link->id || !link->peer_nonce || size != 32 + 64) return false;

    identity::PublicKey key;
    identity::Signature signature;
    std::copy_n(body, 32, key.begin());
    std::copy_n(body + 32, 64, signature.begin());
    const auto message = protocol::hello_signed_data(link->my_nonce, *link->peer_nonce);
    if (!identity::verify(key, message.data(), message.size(), signature)) {
        logging::warn("[Безопасность] Сосед предъявил неверную подпись, соединение закрыто");
        return false;
    }

    const NodeId id = identity::node_id_of(key);
    if (link->dialer) {
        if (auto target = targets_.find(link->dial_key); target != targets_.end()) target->second.id = id;
    }
    if (id == self_.id) {
        link->session->shutdown(protocol::CLOSE_SELF);
        return true;
    }
    if (!resolve_duplicate(link, id)) return true;

    // Считаем только представившихся: посторонний не может занять место
    if (!link->dialer && config_.max_listeners && inbound_links() >= *config_.max_listeners) {
        logging::warn("[Сеть] Входящее соединение от ", identity::short_id(id), " отклонено: достигнут предел ",
                      *config_.max_listeners);
        link->session->shutdown(protocol::CLOSE_FULL);
        return true;
    }

    link->id = id;
    link->last_heard = Clock::now();
    links_by_id_[id] = link;
    link->session->admit();
    logging::info("[Сеть] Сосед подключён: ", identity::short_id(id), " (", link->session->remote_address(), ")");

    send_control(link, protocol::CTRL_READY, nullptr, 0);
    db_.for_each([&](const NodeId&, const routing::NodeInfo&, const std::vector<uint8_t>& encoded) {
        send_control(link, protocol::CTRL_NODE_INFO, encoded.data(), encoded.size());
    });
    return true;
}

// Между двумя узлами остаётся одно соединение, и обе стороны выбирают одно и то же:
// начатое меньшим идентификатором. Если их начала одна сторона, старое уже мертво.
bool MeshNode::resolve_duplicate(const std::shared_ptr<Link>& link, const NodeId& id) {
    const auto it = links_by_id_.find(id);
    if (it == links_by_id_.end()) return true;
    const auto existing = it->second;

    const bool new_better = existing->dialer == link->dialer || (link->dialer == (self_.id < id));
    if (!new_better) {
        link->session->shutdown(protocol::CLOSE_DUPLICATE);
        return false;
    }
    links_by_id_.erase(it);
    existing->id.reset();
    existing->usable = false;
    existing->session->shutdown(protocol::CLOSE_DUPLICATE);
    return true;
}

std::size_t MeshNode::inbound_links() const {
    return static_cast<std::size_t>(std::count_if(links_by_id_.begin(), links_by_id_.end(),
        [](const auto& item) { return !item.second->dialer; }));
}

void MeshNode::on_session_closed(const QuicSession::Ref& session, const QuicSession::CloseInfo& info) {
    if (const auto dial_it = pending_dials_.find(session.get()); dial_it != pending_dials_.end()) {
        if (auto target = targets_.find(dial_it->second); target != targets_.end()) {
            DialTarget& t = target->second;
            t.in_progress = false;
            const bool rejected = info.pin_mismatch || info.transport_status == QUIC_STATUS_BAD_CERTIFICATE ||
                                  info.transport_status == QUIC_STATUS_REQUIRED_CERTIFICATE;
            if (rejected && !t.warned) {
                t.warned = true;
                logging::error("[Безопасность] Узел ", dial_it->second, " не из этой сети: код приглашения не совпадает. "
                               "Данные не передавались.");
            }
            t.retry_after = Clock::now() + (info.peer_code == protocol::CLOSE_FULL ? DIAL_RETRY_FULL : DIAL_RETRY);
            if (info.closed_by_peer && info.peer_code == protocol::CLOSE_FULL && !t.warned) {
                t.warned = true;
                logging::warn("Узел ", dial_it->second, " не принимает новые соединения (предел --listeners). "
                              "Повторяю попытки...");
            }
        }
        pending_dials_.erase(dial_it);
    }

    const auto it = links_.find(session.get());
    if (it == links_.end()) return;
    const auto link = it->second;
    links_.erase(it);
    if (link->id) {
        const auto by_id = links_by_id_.find(*link->id);
        if (by_id != links_by_id_.end() && by_id->second == link) {
            links_by_id_.erase(by_id);
            if (!stopping_) {
                logging::info("[Сеть] Сосед отключился: ", identity::short_id(*link->id));
                schedule_originate();
                schedule_recompute();
            }
        }
    }
}

// --- Карта сети ---

void MeshNode::schedule_originate() {
    if (originate_scheduled_ || stopping_) return;
    originate_scheduled_ = true;
    originate_timer_.expires_after(ORIGINATE_DELAY);
    originate_timer_.async_wait([this](boost::system::error_code ec) {
        originate_scheduled_ = false;
        if (!ec && !stopping_) originate();
    });
}

void MeshNode::originate() {
    routing::NodeInfo info;
    info.signing_key = self_.signing_public;
    info.static_key = self_.static_key.public_key;
    // Часы, чтобы после перезапуска номер был больше прежнего
    sequence_ = std::max(sequence_ + 1, now_ms_wall());
    info.sequence = sequence_;
    info.name = config_.name;
    info.services = config_.services;
    for (const auto& [id, link] : links_by_id_) {
        if (link->usable && info.neighbors.size() < routing::MAX_NEIGHBORS) info.neighbors.push_back(id);
    }
    const auto encoded = routing::encode_node_info(info, self_);
    db_.set_self(encoded, info);
    last_originate_ = Clock::now();
    flood(encoded, nullptr);
    schedule_recompute();
}

void MeshNode::flood(const std::vector<uint8_t>& encoded, const Link* except) {
    for (const auto& [id, link] : links_by_id_) {
        if (link.get() == except || !link->control_out) continue;
        // Сведения обновляются регулярно, поэтому при заторе можно пропустить
        if (link->control_out->congested()) continue;
        send_control(link, protocol::CTRL_NODE_INFO, encoded.data(), encoded.size());
    }
}

void MeshNode::schedule_recompute() {
    if (recompute_scheduled_ || stopping_) return;
    recompute_scheduled_ = true;
    recompute_timer_.expires_after(RECOMPUTE_DELAY);
    recompute_timer_.async_wait([this](boost::system::error_code ec) {
        recompute_scheduled_ = false;
        if (!ec && !stopping_) recompute_routes();
    });
}

std::string MeshNode::describe(const NodeId& id) const {
    const auto* info = db_.find(id);
    const std::string short_form = identity::short_id(id);
    return info && !info->name.empty() ? info->name + " (" + short_form + ")" : short_form;
}

void MeshNode::recompute_routes() {
    std::vector<NodeId> direct;
    for (const auto& [id, link] : links_by_id_) {
        if (link->usable) direct.push_back(id);
    }
    auto routes = db_.compute_routes(direct);

    for (const auto& [id, route] : routes) {
        const auto old = routes_.find(id);
        if (old != routes_.end() && old->second.hops == route.hops) continue;
        if (route.hops == 1) {
            logging::info("[Маршрут] Узел ", describe(id), " доступен напрямую");
        } else {
            logging::info("[Маршрут] Узел ", describe(id), " доступен через ", route.hops - 1, " промежуточных");
        }
    }
    for (const auto& [id, route] : routes_) {
        if (!routes.contains(id)) logging::info("[Маршрут] Узел ", describe(id), " недоступен");
    }
    routes_ = std::move(routes);
    reconcile_proxies();
}

std::shared_ptr<MeshNode::Link> MeshNode::next_hop(const NodeId& dst) const {
    const auto route = routes_.find(dst);
    if (route == routes_.end()) return nullptr;
    const auto link = links_by_id_.find(route->second.next_hop);
    return link == links_by_id_.end() || !link->second->usable ? nullptr : link->second;
}

// --- Маршрутизируемые потоки ---

void MeshNode::on_routed_stream(const QuicByteStream::Ref& stream) {
    auto reader = std::make_shared<StreamHeaderReader>(*this, stream);
    stream->set_handler(reader);
    reader->start();
}

void MeshNode::on_stream_header(const QuicByteStream::Ref& stream, const protocol::StreamHeader& header,
                                std::vector<uint8_t>&& rest) {
    bool for_me = header.dst == self_.id;
#ifdef QUOKKA_TEST_HOOKS
    for_me = for_me || evil_terminate_;
#endif
    if (for_me) {
        const auto* info = db_.find(header.src);
        std::optional<noise::Key> expected;
        if (info) expected = info->static_key;
        SecureChannel::respond(io_, stream, self_, header.dst, header.src, expected,
            [this](const SecureChannel::Ref& channel, const std::vector<uint8_t>& request) {
                return on_channel_request(channel, request);
            }, std::move(rest));
        return;
    }
    relay_stream(stream, header, std::move(rest));
}

void MeshNode::relay_stream(const QuicByteStream::Ref& stream, const protocol::StreamHeader& header,
                            std::vector<uint8_t>&& rest) {
    const auto link = header.ttl > 1 ? next_hop(header.dst) : nullptr;
    auto next = link ? QuicByteStream::open(io_, link->session->handle(), false) : nullptr;
    if (!next) {
        stream->set_handler(nullptr);
        stream->abort();
        return;
    }
    protocol::StreamHeader forwarded = header;
    --forwarded.ttl;
    const auto encoded = protocol::encode_stream_header(forwarded);
    next->send(encoded.data(), encoded.size());

    std::function<void(const uint8_t*, std::size_t)> tap;
#ifdef QUOKKA_TEST_HOOKS
    if (!evil_tap_.empty()) tap = [this](const uint8_t* data, std::size_t size) { evil_tap(data, size); };
#endif
    auto relay = std::make_shared<StreamRelay>(stats_, stream, next, std::move(tap));
#ifdef QUOKKA_TEST_HOOKS
    relay->evil_truncate = evil_truncate_;
#endif
    relay->start(std::move(rest));
}

SecureChannel::Ref MeshNode::open_channel(const NodeId& dst, std::vector<uint8_t> request, SecureChannel::Callbacks callbacks) {
    const auto* info = db_.find(dst);
    const auto link = next_hop(dst);
    if (!info || !link) return nullptr;
    auto stream = QuicByteStream::open(io_, link->session->handle(), false);
    if (!stream) return nullptr;
    const auto header = protocol::encode_stream_header({protocol::DEFAULT_TTL, dst, self_.id});
    stream->send(header.data(), header.size());
    return SecureChannel::initiate(io_, stream, self_, dst, info->static_key, std::move(request), std::move(callbacks));
}

bool MeshNode::on_channel_request(const SecureChannel::Ref& channel, const std::vector<uint8_t>& request) {
    if (request.empty()) return false;

    if (request[0] == protocol::CHANNEL_TCP && request.size() == 2) {
        const uint8_t index = request[1];
        // Номер сверяем со своим списком: пир получает только то, что мы объявили
        if (index >= config_.services.size() || config_.services[index].proto != ServiceProto::Tcp) {
            logging::warn("[Безопасность] Узел ", identity::short_id(channel->peer()), " запросил несуществующий TCP-сервис");
            return false;
        }
        auto bridge = std::make_shared<TcpBridge>(io_, stats_);
        bridge->set_channel(channel);
        channel->set_callbacks(bridge->callbacks());
        bridge->connect_target(config_.services[index].port);
        return true;
    }

    if (request[0] == protocol::CHANNEL_UDP && request.size() == 5) {
        const uint32_t id = (uint32_t(request[1]) << 24) | (uint32_t(request[2]) << 16) |
                            (uint32_t(request[3]) << 8) | uint32_t(request[4]);
        const NodeId peer = channel->peer();
        const std::size_t existing = static_cast<std::size_t>(std::count_if(udp_sessions_.begin(), udp_sessions_.end(),
            [&](const auto& item) { return std::get<0>(item.first) == peer && !std::get<1>(item.first); }));
        const SessionKey key{peer, false, id};
        if (existing >= MAX_SESSIONS_PER_PEER || udp_sessions_.contains(key)) return false;

        auto session = std::make_shared<UdpSession>();
        session->peer = peer;
        session->id = id;
        session->initiator = false;
        session->ready = true;
        session->channel = channel;
        session->send_key = channel->keys().datagram_r2i;
        session->recv_key = channel->keys().datagram_i2r;
        session->targets = std::make_unique<UdpTargetFlows>(io_, stats_,
            [this, weak = std::weak_ptr<UdpSession>(session)](std::vector<uint8_t>&& inner) {
                const auto current = weak.lock();
                return current && send_session_datagram(*current, inner);
            });
        udp_sessions_[key] = session;

        SecureChannel::Callbacks callbacks;
        callbacks.on_data = [channel](std::vector<uint8_t>&&) { channel->abort(); };
        callbacks.on_closed = [this, key](bool) { udp_sessions_.erase(key); };
        channel->set_callbacks(std::move(callbacks));
        return true;
    }
    return false;
}

// --- Сервисы других узлов ---

const OpenRule* MeshNode::find_open_rule(const NodeId& owner, const routing::NodeInfo& info, const Service& service) const {
    const std::string hex = identity::to_hex(owner.data(), owner.size());
    for (const OpenRule& rule : config_.open_rules) {
        if (rule.port != 0 && rule.port != service.port) continue;
        if (!rule.node.empty() && rule.node != info.name && !hex.starts_with(rule.node)) continue;
        return &rule;
    }
    return nullptr;
}

void MeshNode::reconcile_proxies() {
    // Закрываем порты исчезнувших узлов. При временной потере маршрута порт остаётся:
    // игра не теряет сокет, а трафик пойдёт снова, как только маршрут найдётся.
    for (auto it = proxies_.begin(); it != proxies_.end();) {
        const auto* info = db_.find(it->first.first);
        const bool alive = info && it->first.second < info->services.size() &&
                           info->services[it->first.second] == it->second.service;
        if (alive) {
            ++it;
        } else {
            logging::info("[Сервис] ", to_string(it->second.service.proto), " ", it->second.service.port,
                          ": узел исчез, локальный порт ", it->second.local_port, " закрыт");
            close_proxy(it->second);
            it = proxies_.erase(it);
        }
    }

    db_.for_each([&](const NodeId& owner, const routing::NodeInfo& info, const std::vector<uint8_t>&) {
        if (owner == self_.id || !routes_.contains(owner)) return;
        for (std::size_t i = 0; i < info.services.size(); ++i) {
            const ProxyKey key{owner, static_cast<uint8_t>(i)};
            const Service& service = info.services[i];
            if (proxies_.contains(key) || failed_proxies_.contains(key)) continue;

            const OpenRule* rule = find_open_rule(owner, info, service);
            if (!rule) {
                if (announced_.insert(key).second) {
                    logging::info("[Сервис] В сети есть ", to_string(service.proto), " ", service.port, " на узле ",
                                  describe(owner), ". Чтобы пользоваться им здесь, добавьте --open ", service.port);
                }
                continue;
            }
            // Правило на конкретный порт открывает один сервис, а --open all — все
            const bool taken = rule->port != 0 && std::any_of(proxies_.begin(), proxies_.end(), [&](const auto& item) {
                return item.second.service == service;
            });
            if (taken) {
                if (announced_.insert(key).second) {
                    logging::info("[Сервис] ", to_string(service.proto), " ", service.port, " есть и на узле ",
                                  describe(owner), ". Чтобы открыть его отдельно: --open ",
                                  identity::short_id(owner), ":", service.port, "=<локальный порт>");
                }
                continue;
            }
            open_proxy(owner, static_cast<uint8_t>(i), service, *rule);
        }
    });
}

void MeshNode::open_proxy(const NodeId& owner, uint8_t index, const Service& service, const OpenRule& rule) {
    const ProxyKey key{owner, index};
    const bool required = rule.local_port != 0;
    const uint16_t wanted = required ? rule.local_port : service.port;
    const bool reserved = !required && std::find(config_.services.begin(), config_.services.end(),
                                                 Service{service.proto, wanted}) != config_.services.end();

    Proxy proxy;
    proxy.owner = owner;
    proxy.index = index;
    proxy.service = service;
    bool opened = false;
    for (const uint16_t attempt : {reserved ? uint16_t{0} : wanted, uint16_t{0}}) {
        try {
            if (service.proto == ServiceProto::Udp) {
                proxy.udp = std::make_unique<UdpClientEndpoint>(io_, stats_, index, attempt,
                    [this, owner](std::vector<uint8_t>&& inner) { return send_to_service(owner, std::move(inner)); });
                proxy.local_port = proxy.udp->local_port();
            } else {
                auto acceptor = std::make_shared<tcp::acceptor>(io_);
                const tcp::endpoint address(boost::asio::ip::address_v4::loopback(), attempt);
                acceptor->open(address.protocol());
                acceptor->set_option(tcp::acceptor::reuse_address(true));
                acceptor->bind(address);
                acceptor->listen();
                proxy.local_port = acceptor->local_endpoint().port();
                proxy.acceptor = acceptor;
                do_accept(acceptor, owner, index);
            }
            opened = true;
            break;
        } catch (const boost::system::system_error& e) {
            if (required) {
                logging::error("[Сервис] Не удалось открыть порт ", wanted, " из --open: ", e.code().message());
                failed_proxies_.insert(key);
                return;
            }
        }
    }
    if (!opened) {
        failed_proxies_.insert(key);
        return;
    }

    if (proxy.local_port == wanted) {
        logging::info("[Сервис] ", to_string(service.proto), " ", service.port, " узла ", describe(owner),
                      " готов: подключайтесь к 127.0.0.1:", proxy.local_port);
    } else {
        logging::info("[Сервис] ", to_string(service.proto), " ", service.port, " узла ", describe(owner),
                      " готов: порт ", wanted, " занят, подключайтесь к 127.0.0.1:", proxy.local_port);
    }
    proxies_.emplace(key, std::move(proxy));
}

void MeshNode::do_accept(const std::shared_ptr<tcp::acceptor>& acceptor, const NodeId& owner, uint8_t index) {
    acceptor->async_accept([this, acceptor, owner, index](boost::system::error_code ec, tcp::socket socket) {
        // Порт закрывается раньше уничтожения узла, поэтому до этой проверки this не трогаем
        if (ec == boost::asio::error::operation_aborted || !acceptor->is_open()) return;
        if (!ec) connect_tcp(owner, index, std::move(socket));
        do_accept(acceptor, owner, index);
    });
}

void MeshNode::close_proxy(Proxy& proxy) {
    if (proxy.acceptor) {
        boost::system::error_code ec;
        proxy.acceptor->close(ec);
    }
    proxy.udp.reset();
}

void MeshNode::connect_tcp(const NodeId& owner, uint8_t index, tcp::socket socket) {
#ifdef QUOKKA_TEST_HOOKS
    if (evil_service_ >= 0) index = static_cast<uint8_t>(evil_service_);
#endif
    auto bridge = std::make_shared<TcpBridge>(io_, stats_, std::move(socket));
    auto channel = open_channel(owner, {protocol::CHANNEL_TCP, index}, bridge->callbacks());
    if (!channel) {
        logging::warn("[TCP] Узел ", describe(owner), " сейчас недоступен, подключение сброшено");
        return;
    }
    bridge->set_channel(channel);
}

// --- Сквозные UDP-сессии ---

bool MeshNode::send_to_service(const NodeId& owner, std::vector<uint8_t>&& inner) {
#ifdef QUOKKA_TEST_HOOKS
    if (evil_service_ >= 0 && inner.size() > 1) inner[1] = static_cast<uint8_t>(evil_service_);
#endif
    auto it = client_sessions_.find(owner);
    if (it == client_sessions_.end()) {
        auto session = std::make_shared<UdpSession>();
        session->peer = owner;
        session->initiator = true;
        fill_random(session->id);
        const SessionKey key{owner, true, session->id};

        SecureChannel::Callbacks callbacks;
        callbacks.on_ready = [this, weak = std::weak_ptr<UdpSession>(session)] {
            const auto current = weak.lock();
            if (!current || !current->channel) return;
            current->send_key = current->channel->keys().datagram_i2r;
            current->recv_key = current->channel->keys().datagram_r2i;
            current->ready = true;
            for (const auto& queued : current->pending) send_session_datagram(*current, queued);
            current->pending.clear();
        };
        callbacks.on_data = [this, key](std::vector<uint8_t>&&) {
            if (const auto found = udp_sessions_.find(key); found != udp_sessions_.end() && found->second->channel) {
                found->second->channel->abort();
            }
        };
        callbacks.on_closed = [this, key, owner](bool) {
            udp_sessions_.erase(key);
            if (const auto found = client_sessions_.find(owner); found != client_sessions_.end() && found->second->id == std::get<2>(key)) {
                client_sessions_.erase(found);
            }
        };

        const uint32_t id = session->id;
        const std::vector<uint8_t> request{protocol::CHANNEL_UDP, uint8_t(id >> 24), uint8_t(id >> 16), uint8_t(id >> 8), uint8_t(id)};
        udp_sessions_[key] = session;
        client_sessions_[owner] = session;
        session->channel = open_channel(owner, request, std::move(callbacks));
        if (!session->channel) {
            udp_sessions_.erase(key);
            client_sessions_.erase(owner);
            return false;
        }
        it = client_sessions_.find(owner);
    }

    UdpSession& session = *it->second;
    if (!session.ready) {
        if (session.pending.size() >= MAX_PENDING_DATAGRAMS) return false;
        session.pending.push_back(std::move(inner));
        return true;
    }
    return send_session_datagram(session, inner);
}

bool MeshNode::send_session_datagram(UdpSession& session, const std::vector<uint8_t>& inner) {
    const auto link = next_hop(session.peer);
    if (!link) return false;

    protocol::RoutedHeader header;
    header.ttl = protocol::DEFAULT_TTL;
    header.dst = session.peer;
    header.src = self_.id;
    header.from_initiator = session.initiator ? 1 : 0;
    header.session = session.id;

    std::vector<uint8_t> pkt(protocol::ROUTED_HEADER_SIZE + protocol::DG_COUNTER_SIZE);
    protocol::write_routed_header(pkt.data(), header);
    const uint64_t counter = session.send_counter++;
    for (std::size_t i = 0; i < protocol::DG_COUNTER_SIZE; ++i) {
        pkt[protocol::ROUTED_HEADER_SIZE + i] = uint8_t(counter >> (56 - 8 * i));
    }
    const auto cipher = noise::seal(session.send_key, counter, protocol::routed_aad(pkt.data()),
                                    protocol::ROUTED_AAD_SIZE, inner.data(), inner.size());
    pkt.insert(pkt.end(), cipher.begin(), cipher.end());
    return link->session->send_datagram(std::move(pkt));
}

void MeshNode::on_session_datagram(const QuicSession::Ref& session, std::vector<uint8_t>&& pkt) {
    if (pkt.empty()) return;
    const auto link_it = links_.find(session.get());
    if (link_it == links_.end() || !link_it->second->id) return;

    switch (pkt[0]) {
    case protocol::DG_ROUTED:
        on_routed_datagram(std::move(pkt));
        break;
    case protocol::DG_PING:
        pkt[0] = protocol::DG_PONG;
        session->send_datagram(std::move(pkt));
        break;
    case protocol::DG_PONG: {
        int64_t sent = 0;
        if (pkt.size() != 1 + sizeof(sent)) return;
        std::memcpy(&sent, pkt.data() + 1, sizeof(sent));
        const int64_t sample = now_us() - sent;
        if (sample < 0 || sample > 60'000'000) return;
        const int64_t prev = link_it->second->rtt_us.load();
        link_it->second->rtt_us = prev < 0 ? sample : (prev * 7 + sample) / 8;
        break;
    }
    default:
        break;
    }
}

void MeshNode::on_routed_datagram(std::vector<uint8_t>&& pkt) {
    const auto header = protocol::parse_routed_header(pkt);
    if (!header) return;

    if (header->dst != self_.id) {
        if (header->ttl <= 1) return;
        const auto link = next_hop(header->dst);
        if (!link) return;
        pkt[1] = header->ttl - 1;
#ifdef QUOKKA_TEST_HOOKS
        if (!evil_tap_.empty()) evil_tap(pkt.data(), pkt.size());
#endif
        ++stats_.relayed_datagrams;
        link->session->send_datagram(std::move(pkt));
        return;
    }

    const SessionKey key{header->src, header->from_initiator == 0, header->session};
    const auto it = udp_sessions_.find(key);
    if (it == udp_sessions_.end() || !it->second->ready) return;
    UdpSession& session = *it->second;

    uint64_t counter = 0;
    for (std::size_t i = 0; i < protocol::DG_COUNTER_SIZE; ++i) {
        counter = (counter << 8) | pkt[protocol::ROUTED_HEADER_SIZE + i];
    }
    const std::size_t offset = protocol::ROUTED_HEADER_SIZE + protocol::DG_COUNTER_SIZE;
    const auto inner = noise::open(session.recv_key, counter, protocol::routed_aad(pkt.data()), protocol::ROUTED_AAD_SIZE,
                                   pkt.data() + offset, pkt.size() - offset);
    // Счётчик учитываем только после проверки подлинности: иначе подделка сдвинула бы окно
    if (!inner || !session.replay.accept(counter)) return;
    on_session_inner(session, *inner);
}

void MeshNode::on_session_inner(UdpSession& session, const std::vector<uint8_t>& inner) {
    const auto header = protocol::parse_udp_header(inner);
    if (!header) return;
    const uint8_t* payload = inner.data() + protocol::UDP_HEADER_SIZE;
    const std::size_t length = inner.size() - protocol::UDP_HEADER_SIZE;

    if (!session.initiator && header->type == protocol::UDP_TO_TARGET) {
        if (header->service >= config_.services.size()) return;
        const Service& service = config_.services[header->service];
        if (service.proto != ServiceProto::Udp || !session.targets) return;
        session.targets->on_packet(header->service, service.port, header->flow, payload, length);
    } else if (session.initiator && header->type == protocol::UDP_REPLY) {
        const auto proxy = proxies_.find({session.peer, header->service});
        if (proxy == proxies_.end() || !proxy->second.udp) return;
        ++stats_.udp_packets_received;
        proxy->second.udp->on_reply(header->flow, payload, length);
    }
}

#ifdef QUOKKA_TEST_HOOKS
void MeshNode::evil_tap(const void* data, std::size_t size) const {
    std::ofstream out(evil_tap_, std::ios::binary | std::ios::app);
    out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
}
#endif
