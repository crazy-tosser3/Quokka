#include "core/quic_stream.hpp"

#include "core/quic_runtime.hpp"

#include <boost/asio/post.hpp>

QuicByteStream::Ref QuicByteStream::open(boost::asio::io_context& io, HQUIC connection, bool unidirectional) {
    Ref self(new QuicByteStream(io));
    auto* holder = new Ref(self);
    HQUIC stream = nullptr;
    if (QUIC_FAILED(quic::api->StreamOpen(
            connection, unidirectional ? QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL : QUIC_STREAM_OPEN_FLAG_NONE,
            &QuicByteStream::callback, holder, &stream))) {
        delete holder;
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(self->stream_mutex_);
        self->stream_ = stream;
    }
    if (QUIC_FAILED(quic::api->StreamStart(stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
        {
            std::lock_guard<std::mutex> lock(self->stream_mutex_);
            self->stream_ = nullptr;
        }
        quic::api->StreamClose(stream);
        delete holder;
        return nullptr;
    }
    return self;
}

QuicByteStream::Ref QuicByteStream::accept(boost::asio::io_context& io, HQUIC stream) {
    Ref self(new QuicByteStream(io));
    self->stream_ = stream;
    quic::api->SetCallbackHandler(stream, reinterpret_cast<void*>(&QuicByteStream::callback), new Ref(self));
    return self;
}

bool QuicByteStream::send(const void* data, std::size_t size) {
    QUIC_BUFFER* buffer = quic::make_buffer(data, size);
    send_in_flight_ += size;

    std::lock_guard<std::mutex> lock(stream_mutex_);
    if (!stream_ || QUIC_FAILED(quic::api->StreamSend(stream_, buffer, 1, QUIC_SEND_FLAG_NONE, buffer))) {
        send_in_flight_ -= size;
        quic::free_buffer(buffer);
        return false;
    }
    return true;
}

void QuicByteStream::shutdown_stream(QUIC_STREAM_SHUTDOWN_FLAGS flags) {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    if (stream_) quic::api->StreamShutdown(stream_, flags, 0);
}

void QuicByteStream::finish() {
    shutdown_stream(QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL);
}

void QuicByteStream::abort() {
    shutdown_stream(QUIC_STREAM_SHUTDOWN_FLAG_ABORT);
}

void QuicByteStream::consumed(std::size_t size) {
    const std::size_t left = recv_buffered_ -= size;
    if (left < MAX_BUFFERED / 2 && recv_paused_.exchange(false)) {
        std::lock_guard<std::mutex> lock(stream_mutex_);
        if (stream_) quic::api->StreamReceiveSetEnabled(stream_, TRUE);
    }
}

QUIC_STATUS QUIC_API QuicByteStream::callback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event) {
    auto* holder = static_cast<Ref*>(context);
    Ref self = *holder;

    // Обработчик может заменить сам себя, поэтому берём копию на время вызова
    const auto dispatch = [self](auto&& fn) {
        boost::asio::post(self->io_, [self, fn = std::forward<decltype(fn)>(fn)]() mutable {
            if (auto handler = self->handler_) fn(*handler);
        });
    };

    switch (event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        std::vector<uint8_t> data;
        data.reserve(static_cast<std::size_t>(event->RECEIVE.TotalBufferLength));
        for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i) {
            const QUIC_BUFFER& buf = event->RECEIVE.Buffers[i];
            data.insert(data.end(), buf.Buffer, buf.Buffer + buf.Length);
        }
        if (!data.empty()) {
            const std::size_t buffered = self->recv_buffered_ += data.size();
            if (buffered >= MAX_BUFFERED && !self->recv_paused_.exchange(true)) {
                quic::api->StreamReceiveSetEnabled(stream, FALSE);
            }
            dispatch([data = std::move(data)](Handler& handler) mutable { handler.on_stream_data(std::move(data)); });
        }
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        auto* buffer = static_cast<QUIC_BUFFER*>(event->SEND_COMPLETE.ClientContext);
        const std::size_t size = buffer->Length;
        quic::free_buffer(buffer);
        const std::size_t before = self->send_in_flight_.fetch_sub(size);
        if (before >= MAX_BUFFERED && before - size < MAX_BUFFERED) {
            dispatch([](Handler& handler) { handler.on_stream_writable(); });
        }
        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        dispatch([](Handler& handler) { handler.on_stream_fin(); });
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        self->abort();
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        {
            std::lock_guard<std::mutex> lock(self->stream_mutex_);
            self->stream_ = nullptr;
        }
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) quic::api->StreamClose(stream);
        // Разрываем цикл ссылок поток <-> обработчик
        boost::asio::post(self->io_, [self] {
            if (auto handler = std::move(self->handler_)) handler->on_stream_closed();
        });
        delete holder;
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}
