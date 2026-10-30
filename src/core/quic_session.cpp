#include "core/quic_session.hpp"

#include "core/log.hpp"
#include "core/protocol.hpp"
#include "core/quic_runtime.hpp"

#include <boost/asio/post.hpp>
#include <openssl/crypto.h>

#include <chrono>
#include <stdexcept>

namespace {

std::string address_of(HQUIC connection) {
    QUIC_ADDR addr{};
    uint32_t size = sizeof(addr);
    if (QUIC_FAILED(quic::api->GetParam(connection, QUIC_PARAM_CONN_REMOTE_ADDRESS, &size, &addr))) {
        return {};
    }
    QUIC_ADDR_STR str{};
    if (!QuicAddrToString(&addr, &str)) return {};
    return str.Address;
}

// Чужие узлы могут стучаться часто, а лог не должен этим забиваться
bool should_log_rejection() {
    using namespace std::chrono;
    static std::atomic<int64_t> last_second{0};
    const int64_t now = duration_cast<seconds>(steady_clock::now().time_since_epoch()).count();
    return last_second.exchange(now) != now;
}

}

QuicSession::QuicSession(Context& context) : context_(context) {}

QuicSession::Ref QuicSession::connect(Context& context, const std::string& host, uint16_t port) {
    Ref session(new QuicSession(context));
    HQUIC connection = nullptr;
    QUIC_STATUS status = quic::api->ConnectionOpen(
        quic::registration, &QuicSession::callback, session.get(), &connection);
    if (QUIC_FAILED(status)) throw std::runtime_error("ConnectionOpen failed");

    session->connection_ = connection;
    session->self_ = session;
    ++context.open_sessions;

    status = quic::api->ConnectionStart(
        connection, quic::client_configuration, QUIC_ADDRESS_FAMILY_INET, host.c_str(), port);
    if (QUIC_FAILED(status)) {
        quic::api->ConnectionClose(connection);
        session->connection_ = nullptr;
        session->self_.reset();
        --context.open_sessions;
        throw std::runtime_error("ConnectionStart failed");
    }
    return session;
}

QUIC_STATUS QuicSession::accept(Context& context, HQUIC connection) {
    Ref session(new QuicSession(context));
    session->connection_ = connection;
    session->self_ = session;
    ++context.open_sessions;

    quic::api->SetCallbackHandler(connection, reinterpret_cast<void*>(&QuicSession::callback), session.get());
    const QUIC_STATUS status = quic::api->ConnectionSetConfiguration(connection, quic::server_configuration);
    if (QUIC_FAILED(status)) {
        // MsQuic сам закроет отклонённое соединение и не будет вызывать callback
        session->self_.reset();
        --context.open_sessions;
    }
    return status;
}

bool QuicSession::send_datagram(std::vector<uint8_t>&& pkt) {
    if (!connection_) return false;

    const std::size_t max_len = max_datagram_.load();
    if (max_len == 0 || pkt.size() > max_len) {
        if (max_len != 0 && !oversize_warned_) {
            logging::warn("[UDP] Пакет в ", pkt.size(), " байт не помещается в датаграмму (предел ",
                          max_len, ") и будет отброшен");
            oversize_warned_ = true;
        }
        return false;
    }
    if (datagrams_in_flight_.load() >= MAX_DATAGRAMS_IN_FLIGHT) return false;

    QUIC_BUFFER* buffer = quic::make_buffer(pkt.data(), pkt.size());
    ++datagrams_in_flight_;
    if (QUIC_FAILED(quic::api->DatagramSend(connection_, buffer, 1, QUIC_SEND_FLAG_NONE, buffer))) {
        --datagrams_in_flight_;
        quic::free_buffer(buffer);
        return false;
    }
    return true;
}

void QuicSession::shutdown(uint64_t code) {
    if (connection_) quic::api->ConnectionShutdown(connection_, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, code);
}

void QuicSession::abandon() {
    if (connection_) quic::api->ConnectionShutdown(connection_, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, protocol::CLOSE_NORMAL);
}

QUIC_STATUS QuicSession::verify_peer(const QUIC_CONNECTION_EVENT& event) {
    // С USE_PORTABLE_CERTIFICATES сертификат приходит как DER: MsQuic и наш код
    // могут быть собраны с разными версиями OpenSSL, X509* между ними передавать нельзя
    const auto* cert = reinterpret_cast<const QUIC_BUFFER*>(event.PEER_CERTIFICATE_RECEIVED.Certificate);
    const auto pin = cert ? identity::pin_of_certificate(cert->Buffer, cert->Length) : std::nullopt;

    if (!pin || CRYPTO_memcmp(pin->data(), context_.expected_pin.data(), pin->size()) != 0) {
        close_info_.pin_mismatch = true;
        if (should_log_rejection()) {
            logging::warn("[Безопасность] Отклонено подключение ", address_of(connection_),
                          ": ключ не совпадает с ожидаемым");
        }
        return QUIC_STATUS_BAD_CERTIFICATE;
    }
    verified_ = true;
    return QUIC_STATUS_SUCCESS;
}

void QuicSession::finish_close(const CloseInfo& info) {
    context_.events.on_session_closed(shared_from_this(), info);
    quic::api->ConnectionClose(connection_);
    connection_ = nullptr;
    --context_.open_sessions;
    self_.reset();
}

QUIC_STATUS QUIC_API QuicSession::callback(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event) {
    auto* session = static_cast<QuicSession*>(context);
    auto& io = session->context_.io;

    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        return session->verify_peer(*event);

    case QUIC_CONNECTION_EVENT_CONNECTED: {
        // Страховка на случай, если TLS-слой не вызвал проверку сертификата: без неё — никакого доступа
        if (!session->verified_.load()) {
            logging::error("[Безопасность] Соединение без проверенного ключа закрыто");
            quic::api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                          protocol::CLOSE_PROTOCOL_ERROR);
            break;
        }
        session->remote_address_ = address_of(connection);
        boost::asio::post(io, [session, self = session->shared_from_this()] {
            session->context_.events.on_session_ready(self);
        });
        break;
    }

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        const bool unidirectional = event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
        const bool accepted = session->verified_.load() && session->context_.events.on_peer_stream(
            session->shared_from_this(), event->PEER_STREAM_STARTED.Stream, unidirectional);
        return accepted ? QUIC_STATUS_SUCCESS : QUIC_STATUS_NOT_SUPPORTED;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        session->max_datagram_ = event->DATAGRAM_STATE_CHANGED.SendEnabled
            ? event->DATAGRAM_STATE_CHANGED.MaxSendLength : 0;
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        // Датаграммы, как и UDP, можно терять: если поток io_context не успевает, лучше отбросить
        if (session->datagrams_queued_.load() >= MAX_DATAGRAMS_QUEUED) break;
        ++session->datagrams_queued_;
        const QUIC_BUFFER* buf = event->DATAGRAM_RECEIVED.Buffer;
        boost::asio::post(io, [session, self = session->shared_from_this(),
                               pkt = std::vector<uint8_t>(buf->Buffer, buf->Buffer + buf->Length)]() mutable {
            --session->datagrams_queued_;
            session->context_.events.on_session_datagram(self, std::move(pkt));
        });
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (QUIC_DATAGRAM_SEND_STATE_IS_FINAL(event->DATAGRAM_SEND_STATE_CHANGED.State)) {
            quic::free_buffer(event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
            --session->datagrams_in_flight_;
        }
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        session->close_info_.transport_status = event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        session->close_info_.closed_by_peer = true;
        session->close_info_.peer_code = event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
        session->close_info_.handshake_completed = event->SHUTDOWN_COMPLETE.HandshakeCompleted;
        boost::asio::post(io, [session, self = session->shared_from_this(), info = session->close_info_] {
            session->finish_close(info);
        });
        break;
    }

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void drain_sessions(boost::asio::io_context& io, const std::atomic<std::size_t>& open_sessions) {
    quic::api->RegistrationShutdown(quic::registration, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                    protocol::CLOSE_NORMAL);
    io.restart();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (open_sessions.load() > 0 && std::chrono::steady_clock::now() < deadline) {
        io.run_one_for(std::chrono::milliseconds(50));
    }
    if (open_sessions.load() > 0) logging::warn("[QUIC] Не дождались закрытия соединений");
}
