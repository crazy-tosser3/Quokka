#pragma once

#include "core/identity.hpp"
#include "core/noise.hpp"
#include "core/quic_stream.hpp"

#include <boost/asio.hpp>

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Сквозной зашифрованный канал поверх маршрутизируемого потока. Узлы на пути видят только шифротекст.
// Кадр: [длина:2][данные]. Сначала три сообщения Noise, затем зашифрованные записи.
// Пустая запись означает штатный конец данных: простому FIN верить нельзя, его может подделать ретранслятор.
class SecureChannel : public QuicByteStream::Handler, public std::enable_shared_from_this<SecureChannel> {
public:
    using Ref = std::shared_ptr<SecureChannel>;
    using Bytes = std::vector<uint8_t>;

    struct Callbacks {
        std::function<void()> on_ready;              // только у того, кто начал канал
        std::function<void(Bytes&&)> on_data;        // после обработки вызвать consumed_record()
        std::function<void()> on_fin;                // другая сторона штатно закончила отправку
        std::function<void(bool clean)> on_closed;   // clean = false: обрыв, данные могли не дойти
        std::function<void()> on_writable;
    };
    // Отвечающая сторона получает запрос и настраивает callbacks; false отклоняет канал
    using RequestFn = std::function<bool(const Ref&, const Bytes& request)>;

    // Начать канал к узлу, чей статический ключ известен из подписанной карты сети
    static Ref initiate(boost::asio::io_context& io, QuicByteStream::Ref stream, const identity::NodeIdentity& self,
                        const identity::NodeId& peer, const noise::Key& expected_static, Bytes request,
                        Callbacks callbacks);

    // Ответить на канал. local_id — получатель из заголовка потока
    static void respond(boost::asio::io_context& io, QuicByteStream::Ref stream, const identity::NodeIdentity& self,
                        const identity::NodeId& local_id, const identity::NodeId& peer,
                        std::optional<noise::Key> expected_static, RequestFn on_request, Bytes&& initial);

    void set_callbacks(Callbacks callbacks) { callbacks_ = std::move(callbacks); }

    bool send(const void* data, std::size_t size);
    void finish();
    void abort();
    void consumed_record();
    bool congested() const { return stream_ && stream_->congested(); }

    const noise::TransportKeys& keys() const { return keys_; }
    bool initiator() const { return initiator_; }
    const identity::NodeId& peer() const { return peer_; }

    void on_stream_data(std::vector<uint8_t>&& data) override;
    void on_stream_fin() override;
    void on_stream_closed() override;
    void on_stream_writable() override;

private:
    static constexpr std::size_t MAX_RECORD = 16 * 1024;
    static constexpr std::size_t MAX_HANDSHAKE_FRAME = 1024;
    static constexpr std::size_t FRAME_PREFIX = 2;
    static constexpr auto HANDSHAKE_TIMEOUT = std::chrono::seconds(10);

    SecureChannel(boost::asio::io_context& io, QuicByteStream::Ref stream, const noise::KeyPair& local_static,
                  const identity::NodeId& peer, bool initiator, const Bytes& prologue);
    void start_timer();
    bool handle_frame(const uint8_t* data, std::size_t size);
    bool handle_handshake(const uint8_t* data, std::size_t size);
    bool handle_record(const uint8_t* data, std::size_t size);
    bool send_frame(const Bytes& data);
    void established();

    QuicByteStream::Ref stream_;
    boost::asio::steady_timer timer_;
    identity::NodeId peer_;
    bool initiator_;
    noise::Handshake handshake_;
    std::optional<noise::Key> expected_static_;
    Bytes request_;
    RequestFn on_request_;
    Callbacks callbacks_;

    bool established_{false};
    noise::TransportKeys keys_{};
    uint64_t send_counter_{0};
    uint64_t recv_counter_{0};
    Bytes rx_;
    std::deque<std::size_t> pending_records_;
    bool eof_received_{false};
    bool finished_{false};
    bool closed_{false};
};
