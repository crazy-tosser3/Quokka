#pragma once

#include <boost/asio/io_context.hpp>
#include <msquic.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

// QUIC-поток с обратным давлением. Методы вызываются из потока io_context,
// туда же приходят все события Handler, в том порядке, в каком их выдал MsQuic.
class QuicByteStream : public std::enable_shared_from_this<QuicByteStream> {
public:
    using Ref = std::shared_ptr<QuicByteStream>;

    struct Handler {
        virtual ~Handler() = default;
        // Данные считаются занятыми, пока получатель не вызовет consumed()
        virtual void on_stream_data(std::vector<uint8_t>&& data) = 0;
        virtual void on_stream_fin() = 0;
        virtual void on_stream_closed() = 0;  // последнее событие
        virtual void on_stream_writable() {}  // снова можно отправлять, см. congested()
    };

    // Сколько данных держать в памяти в каждую сторону. Дальше приём приостанавливается,
    // и окно QUIC закрывается: отправитель перестаёт слать.
    static constexpr std::size_t MAX_BUFFERED = 1024 * 1024;

    // nullptr, если соединение уже закрыто или кончились потоки
    static Ref open(boost::asio::io_context& io, HQUIC connection, bool unidirectional);
    // Можно вызывать в потоке MsQuic из QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED.
    // Обработчик нужно задать через post в io_context до возврата из обратного вызова.
    static Ref accept(boost::asio::io_context& io, HQUIC stream);

    void set_handler(std::shared_ptr<Handler> handler) { handler_ = std::move(handler); }

    bool send(const void* data, std::size_t size);
    void finish();  // штатное завершение отправки
    void abort();
    void consumed(std::size_t size);
    bool congested() const { return send_in_flight_.load() >= MAX_BUFFERED; }

private:
    explicit QuicByteStream(boost::asio::io_context& io) : io_(io) {}
    static QUIC_STATUS QUIC_API callback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event);
    void shutdown_stream(QUIC_STREAM_SHUTDOWN_FLAGS flags);

    boost::asio::io_context& io_;
    std::shared_ptr<Handler> handler_;

    std::mutex stream_mutex_;
    HQUIC stream_{nullptr};

    std::atomic<std::size_t> send_in_flight_{0};  // отдано в QUIC, но ещё не подтверждено
    std::atomic<std::size_t> recv_buffered_{0};   // получено из QUIC, но ещё не обработано
    std::atomic<bool> recv_paused_{false};
};
