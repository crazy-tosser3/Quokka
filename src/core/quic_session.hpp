#pragma once

#include "core/identity.hpp"

#include <boost/asio/io_context.hpp>
#include <msquic.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Одно QUIC-соединение с соседом, проверенным по ключу сети.
//
// Все вызовы и все поля без std::atomic — только из потока io_context:
// обратные вызовы MsQuic пересылают события туда через post. Это позволяет
// обойтись без блокировок и закрывать handle там же, где он используется.
class QuicSession : public std::enable_shared_from_this<QuicSession> {
public:
    using Ref = std::shared_ptr<QuicSession>;

    struct CloseInfo {
        bool handshake_completed{false};
        bool pin_mismatch{false};        // ключ пира не совпал с ожидаемым
        bool closed_by_peer{false};
        uint64_t peer_code{0};           // CloseCode, если closed_by_peer
        QUIC_STATUS transport_status{QUIC_STATUS_SUCCESS};
    };

    struct Events {
        virtual ~Events() = default;
        // В потоке io_context
        virtual void on_session_ready(const Ref& session) = 0;
        virtual void on_session_datagram(const Ref& session, std::vector<uint8_t>&& pkt) = 0;
        virtual void on_session_closed(const Ref& session, const CloseInfo& info) = 0;
        // В потоке MsQuic! Принять поток: вызвать SetCallbackHandler и вернуть true
        virtual bool on_peer_stream(const Ref& session, HQUIC stream, bool unidirectional) = 0;
    };

    // Общее для всех сессий узла
    struct Context {
        boost::asio::io_context& io;
        Events& events;
        identity::Pin expected_pin;
        std::atomic<std::size_t> open_sessions{0};
    };

    // Бросает std::runtime_error, если соединение не удалось начать
    static Ref connect(Context& context, const std::string& host, uint16_t port);
    // Для QUIC_LISTENER_EVENT_NEW_CONNECTION; при ошибке соединение отклоняется
    static QUIC_STATUS accept(Context& context, HQUIC connection);

    bool send_datagram(std::vector<uint8_t>&& pkt);
    void shutdown(uint64_t code);
    void abandon();  // закрыть, не дожидаясь ответа: пир уже не отвечает

    HQUIC handle() const { return connection_; }
    boost::asio::io_context& io() const { return context_.io; }
    const std::string& remote_address() const { return remote_address_; }
    std::size_t max_datagram_size() const { return max_datagram_.load(); }

    // Разрешение принимать потоки от соседа; выставляет владелец, когда узнал, кто это
    void admit() { admitted_ = true; }
    bool admitted() const { return admitted_.load(); }

private:
    static constexpr std::size_t MAX_DATAGRAMS_IN_FLIGHT = 4096;
    static constexpr std::size_t MAX_DATAGRAMS_QUEUED = 4096;

    explicit QuicSession(Context& context);
    static QUIC_STATUS QUIC_API callback(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event);
    QUIC_STATUS verify_peer(const QUIC_CONNECTION_EVENT& event);
    void finish_close(const CloseInfo& info);

    Context& context_;
    Ref self_;  // держит объект живым, пока MsQuic может вызывать callback
    HQUIC connection_{nullptr};
    std::string remote_address_;
    bool oversize_warned_{false};

    std::atomic<std::size_t> max_datagram_{0};
    std::atomic<std::size_t> datagrams_in_flight_{0};
    std::atomic<std::size_t> datagrams_queued_{0};
    std::atomic<bool> verified_{false};
    std::atomic<bool> admitted_{false};
    CloseInfo close_info_;  // пишется только в потоке MsQuic до SHUTDOWN_COMPLETE
};

// Закрывает все сессии узла и ждёт их завершения. Вызывать после остановки потока io_context.
void drain_sessions(boost::asio::io_context& io, const std::atomic<std::size_t>& open_sessions);
