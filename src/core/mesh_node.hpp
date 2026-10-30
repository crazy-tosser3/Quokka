#pragma once

#include "core/config.hpp"
#include "core/discovery.hpp"
#include "core/identity.hpp"
#include "core/protocol.hpp"
#include "core/quic_session.hpp"
#include "core/quic_stream.hpp"
#include "core/routing.hpp"
#include "core/secure_channel.hpp"
#include "core/stats.hpp"
#include "core/udp_tunnel.hpp"

#include <boost/asio.hpp>
#include <msquic.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

// Узел mesh-сети. Все узлы равны: каждый принимает соединения, сам подключается к соседям,
// открывает свои сервисы, пользуется чужими и передаёт транзитный трафик.
class MeshNode final : private QuicSession::Events {
public:
    MeshNode(boost::asio::io_context& io, const NodeConfig& config, Stats& stats,
             const identity::NetworkKeys& keys, const identity::NodeIdentity& self);
    ~MeshNode() override;

    NodeStatus status() const;
    uint16_t quic_port() const { return quic_port_; }

private:
    using Clock = std::chrono::steady_clock;
    using NodeId = identity::NodeId;
    using Nonce = std::array<uint8_t, 32>;
    using tcp = boost::asio::ip::tcp;

    // --- Соседи ---

    struct Link {
        QuicSession::Ref session;
        bool dialer{false};               // это соединение начали мы
        std::string dial_key;
        Clock::time_point opened_at;
        Nonce my_nonce{};
        std::optional<Nonce> peer_nonce;
        std::optional<NodeId> id;         // есть после проверки подписи соседа
        bool usable{false};               // сосед подтвердил, что принимает потоки
        QuicByteStream::Ref control_out;
        QuicByteStream::Ref control_in;
        std::vector<uint8_t> control_rx;
        std::atomic<int64_t> rtt_us{-1};
        uint64_t received_packets{0};     // для обнаружения пропавшего соседа
        Clock::time_point last_heard;
    };

    // Адрес, к которому можно подключиться
    struct DialTarget {
        std::string host;
        uint16_t port{0};
        bool configured{false};           // из --peer, а не из маяка
        std::optional<NodeId> id;
        Clock::time_point first_seen;
        Clock::time_point last_seen;
        Clock::time_point retry_after;
        bool in_progress{false};
        bool warned{false};
    };

    void on_session_ready(const QuicSession::Ref& session) override;
    void on_session_datagram(const QuicSession::Ref& session, std::vector<uint8_t>&& pkt) override;
    void on_session_closed(const QuicSession::Ref& session, const QuicSession::CloseInfo& info) override;
    bool on_peer_stream(const QuicSession::Ref& session, HQUIC stream, bool unidirectional) override;

    static QUIC_STATUS QUIC_API listener_callback(HQUIC, void* context, QUIC_LISTENER_EVENT* event);
    void start_listener();
    void dial(const std::string& key, DialTarget& target);
    void on_beacon(const boost::asio::ip::address& address, const protocol::Beacon& beacon);
    void do_tick();
    void check_link_alive(const std::shared_ptr<Link>& link, Clock::time_point now);

    void on_control_stream(const std::shared_ptr<Link>& link, const QuicByteStream::Ref& stream);
    void on_control_data(const std::shared_ptr<Link>& link, std::vector<uint8_t>&& data);
    bool handle_control_frame(const std::shared_ptr<Link>& link, uint8_t type, const uint8_t* body, std::size_t size);
    bool handle_hello(const std::shared_ptr<Link>& link, const uint8_t* body, std::size_t size);
    void send_control(const std::shared_ptr<Link>& link, protocol::ControlType type, const uint8_t* body, std::size_t size);
    bool resolve_duplicate(const std::shared_ptr<Link>& link, const NodeId& id);
    std::size_t inbound_links() const;

    // --- Карта сети и маршруты ---

    void schedule_originate();
    void originate();
    void flood(const std::vector<uint8_t>& encoded, const Link* except);
    void schedule_recompute();
    void recompute_routes();
    std::string describe(const NodeId& id) const;
    std::shared_ptr<Link> next_hop(const NodeId& dst) const;

    // --- Потоки ---

    class StreamHeaderReader;
    void on_routed_stream(const QuicByteStream::Ref& stream);
    void on_stream_header(const QuicByteStream::Ref& stream, const protocol::StreamHeader& header, std::vector<uint8_t>&& rest);
    void relay_stream(const QuicByteStream::Ref& stream, const protocol::StreamHeader& header, std::vector<uint8_t>&& rest);
    QuicByteStream::Ref open_routed_stream(const NodeId& dst);
    SecureChannel::Ref open_channel(const NodeId& dst, std::vector<uint8_t> request, SecureChannel::Callbacks callbacks);
    bool on_channel_request(const SecureChannel::Ref& channel, const std::vector<uint8_t>& request);

    // --- Сервисы других узлов на локальных портах ---

    struct Proxy {
        NodeId owner{};
        uint8_t index{0};
        Service service;
        uint16_t local_port{0};
        std::unique_ptr<UdpClientEndpoint> udp;
        std::shared_ptr<tcp::acceptor> acceptor;
    };
    using ProxyKey = std::pair<NodeId, uint8_t>;

    const OpenRule* find_open_rule(const NodeId& owner, const routing::NodeInfo& info, const Service& service) const;
    void reconcile_proxies();
    void open_proxy(const NodeId& owner, uint8_t index, const Service& service, const OpenRule& rule);
    void do_accept(const std::shared_ptr<tcp::acceptor>& acceptor, const NodeId& owner, uint8_t index);
    void close_proxy(Proxy& proxy);
    void connect_tcp(const NodeId& owner, uint8_t index, tcp::socket socket);

    // --- Сквозные UDP-сессии ---

    struct UdpSession {
        NodeId peer{};
        uint32_t id{0};
        bool initiator{false};
        bool ready{false};
        SecureChannel::Ref channel;
        noise::Key send_key{};
        noise::Key recv_key{};
        uint64_t send_counter{0};
        noise::ReplayWindow replay;
        std::unique_ptr<UdpTargetFlows> targets;  // только у отвечающей стороны
        std::deque<std::vector<uint8_t>> pending;
    };
    using SessionKey = std::tuple<NodeId, bool, uint32_t>;  // пир, мы начали, номер

    bool send_to_service(const NodeId& owner, std::vector<uint8_t>&& inner);
    bool send_session_datagram(UdpSession& session, const std::vector<uint8_t>& inner);
    void on_routed_datagram(std::vector<uint8_t>&& pkt);
    void on_session_inner(UdpSession& session, const std::vector<uint8_t>& inner);

    boost::asio::io_context& io_;
    NodeConfig config_;
    Stats& stats_;
    identity::NodeIdentity self_;
    QuicSession::Context sessions_;
    HQUIC quic_listener_{nullptr};
    uint16_t quic_port_{0};

    std::map<QuicSession*, std::shared_ptr<Link>> links_;
    std::map<NodeId, std::shared_ptr<Link>> links_by_id_;
    std::map<QuicSession*, std::string> pending_dials_;
    std::map<std::string, DialTarget> targets_;

    routing::Database db_;
    std::map<NodeId, routing::Route> routes_;
    uint64_t sequence_{0};
    bool originate_scheduled_{false};
    bool recompute_scheduled_{false};
    boost::asio::steady_timer originate_timer_;
    boost::asio::steady_timer recompute_timer_;
    Clock::time_point last_originate_;

    std::map<ProxyKey, Proxy> proxies_;
    std::set<ProxyKey> announced_;
    std::set<ProxyKey> failed_proxies_;

    std::map<SessionKey, std::shared_ptr<UdpSession>> udp_sessions_;
    std::map<NodeId, std::shared_ptr<UdpSession>> client_sessions_;

    std::optional<BeaconSender> beacon_sender_;
    std::optional<BeaconReceiver> beacon_receiver_;
    boost::asio::steady_timer tick_timer_;
    bool stopping_{false};
    Clock::time_point started_at_;
    bool lonely_hint_shown_{false};

    // Для status() из других потоков
    mutable std::mutex status_mutex_;
    std::vector<PeerStatus> peer_status_;

#ifdef QUOKKA_TEST_HOOKS
    std::string evil_tap_;
    bool evil_terminate_{false};
    int evil_service_{-1};
    std::size_t evil_truncate_{0};
    void evil_tap(const void* data, std::size_t size) const;
#endif
};
