#include "core/secure_channel.hpp"

#include "core/log.hpp"
#include "core/protocol.hpp"

#include <algorithm>

SecureChannel::SecureChannel(boost::asio::io_context& io, QuicByteStream::Ref stream, const noise::KeyPair& local_static,
                             const identity::NodeId& peer, bool initiator, const Bytes& prologue)
    : stream_(std::move(stream)),
      timer_(io),
      peer_(peer),
      initiator_(initiator),
      handshake_(initiator, local_static, prologue) {}

SecureChannel::Ref SecureChannel::initiate(boost::asio::io_context& io, QuicByteStream::Ref stream,
                                           const identity::NodeIdentity& self, const identity::NodeId& peer,
                                           const noise::Key& expected_static, Bytes request, Callbacks callbacks) {
    Ref channel(new SecureChannel(io, std::move(stream), self.static_key, peer, true,
                                  protocol::channel_prologue(self.id, peer)));
    channel->expected_static_ = expected_static;
    channel->request_ = std::move(request);
    channel->callbacks_ = std::move(callbacks);
    channel->stream_->set_handler(channel);
    channel->start_timer();
    channel->send_frame(channel->handshake_.write_message({}));
    return channel;
}

void SecureChannel::respond(boost::asio::io_context& io, QuicByteStream::Ref stream, const identity::NodeIdentity& self,
                            const identity::NodeId& local_id, const identity::NodeId& peer,
                            std::optional<noise::Key> expected_static, RequestFn on_request, Bytes&& initial) {
    Ref channel(new SecureChannel(io, std::move(stream), self.static_key, peer, false,
                                  protocol::channel_prologue(peer, local_id)));
    channel->expected_static_ = expected_static;
    channel->on_request_ = std::move(on_request);
    channel->stream_->set_handler(channel);
    channel->start_timer();
    if (!initial.empty()) channel->on_stream_data(std::move(initial));
}

void SecureChannel::start_timer() {
    timer_.expires_after(HANDSHAKE_TIMEOUT);
    timer_.async_wait([weak = weak_from_this()](boost::system::error_code ec) {
        const auto self = weak.lock();
        if (ec || !self || self->established_) return;
        logging::debug("[Канал] Рукопожатие не завершилось вовремя");
        self->abort();
    });
}

bool SecureChannel::send_frame(const Bytes& data) {
    Bytes frame{uint8_t(data.size() >> 8), uint8_t(data.size())};
    frame.insert(frame.end(), data.begin(), data.end());
    return stream_ && stream_->send(frame.data(), frame.size());
}

bool SecureChannel::send(const void* data, std::size_t size) {
    if (!established_ || finished_) return false;
    const auto* cursor = static_cast<const uint8_t*>(data);
    while (size > 0) {
        const std::size_t chunk = std::min(size, MAX_RECORD);
        const auto& key = initiator_ ? keys_.stream_i2r : keys_.stream_r2i;
        if (!send_frame(noise::seal(key, send_counter_++, nullptr, 0, cursor, chunk))) return false;
        cursor += chunk;
        size -= chunk;
    }
    return true;
}

void SecureChannel::finish() {
    if (!established_ || finished_ || !stream_) return;
    const auto& key = initiator_ ? keys_.stream_i2r : keys_.stream_r2i;
    send_frame(noise::seal(key, send_counter_++, nullptr, 0, nullptr, 0));
    finished_ = true;
    stream_->finish();
}

void SecureChannel::abort() {
    if (stream_) stream_->abort();
}

void SecureChannel::consumed_record() {
    if (pending_records_.empty()) return;
    const std::size_t size = pending_records_.front();
    pending_records_.pop_front();
    if (stream_) stream_->consumed(size);
}

void SecureChannel::on_stream_data(std::vector<uint8_t>&& data) {
    if (closed_) return;
    rx_.insert(rx_.end(), data.begin(), data.end());

    std::size_t offset = 0;
    while (rx_.size() - offset >= FRAME_PREFIX) {
        const std::size_t size = (std::size_t(rx_[offset]) << 8) | rx_[offset + 1];
        if (!established_ && size > MAX_HANDSHAKE_FRAME) {
            abort();
            return;
        }
        if (rx_.size() - offset < FRAME_PREFIX + size) break;
        if (!handle_frame(rx_.data() + offset + FRAME_PREFIX, size)) {
            abort();
            return;
        }
        offset += FRAME_PREFIX + size;
    }
    rx_.erase(rx_.begin(), rx_.begin() + static_cast<std::ptrdiff_t>(offset));
}

bool SecureChannel::handle_frame(const uint8_t* data, std::size_t size) {
    return established_ ? handle_record(data, size) : handle_handshake(data, size);
}

bool SecureChannel::handle_handshake(const uint8_t* data, std::size_t size) {
    stream_->consumed(FRAME_PREFIX + size);
    const auto payload = handshake_.read_message(data, size);
    if (!payload) {
        logging::warn("[Безопасность] Рукопожатие с узлом ", identity::short_id(peer_), " не прошло проверку");
        return false;
    }

    if (initiator_) {
        // Промежуточный узел не может подставить свой ключ: ожидаемый взят из подписанной карты
        if (handshake_.remote_static() != *expected_static_) {
            logging::error("[Безопасность] Кто-то на пути подменил ключ узла ", identity::short_id(peer_),
                           ": возможна атака MITM. Соединение разорвано, данные не передавались.");
            return false;
        }
        if (!send_frame(handshake_.write_message(request_))) return false;
        established();
        if (callbacks_.on_ready) callbacks_.on_ready();
        return true;
    }

    if (!handshake_.finished()) {
        return send_frame(handshake_.write_message({}));
    }

    if (!expected_static_ || handshake_.remote_static() != *expected_static_) {
        logging::warn("[Безопасность] Ключ узла ", identity::short_id(peer_), " не совпал с картой сети");
        return false;
    }
    established();
    return on_request_(shared_from_this(), *payload);
}

void SecureChannel::established() {
    established_ = true;
    keys_ = handshake_.split();
    timer_.cancel();
}

bool SecureChannel::handle_record(const uint8_t* data, std::size_t size) {
    const auto& key = initiator_ ? keys_.stream_r2i : keys_.stream_i2r;
    auto plain = noise::open(key, recv_counter_++, nullptr, 0, data, size);
    if (!plain) {
        logging::warn("[Безопасность] Запись от узла ", identity::short_id(peer_), " подделана или повреждена");
        return false;
    }
    if (plain->empty()) {
        stream_->consumed(FRAME_PREFIX + size);
        eof_received_ = true;
        if (callbacks_.on_fin) callbacks_.on_fin();
        return true;
    }
    if (eof_received_) return false;
    pending_records_.push_back(FRAME_PREFIX + size);
    if (callbacks_.on_data) callbacks_.on_data(std::move(*plain));
    return true;
}

void SecureChannel::on_stream_fin() {
    // FIN без зашифрованного признака конца: кто-то на пути пытается обрезать данные
    if (!eof_received_) {
        if (established_) logging::warn("[Безопасность] Поток от узла ", identity::short_id(peer_), " оборван без признака конца");
        abort();
    }
}

void SecureChannel::on_stream_closed() {
    closed_ = true;
    timer_.cancel();
    stream_.reset();
    const auto callbacks = std::move(callbacks_);
    callbacks_ = {};
    on_request_ = nullptr;
    if (callbacks.on_closed) callbacks.on_closed(eof_received_ && finished_);
}

void SecureChannel::on_stream_writable() {
    if (callbacks_.on_writable) callbacks_.on_writable();
}
