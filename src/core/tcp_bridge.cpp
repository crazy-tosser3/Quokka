#include "core/tcp_bridge.hpp"

#include "core/log.hpp"

TcpBridge::TcpBridge(boost::asio::io_context& io, Stats& stats, tcp::socket socket)
    : stats_(stats), socket_(std::move(socket)), tcp_ready_(true) {
    (void)io;
    ++stats_.tcp_bridges;
    set_nodelay();
}

TcpBridge::TcpBridge(boost::asio::io_context& io, Stats& stats) : stats_(stats), socket_(io) {
    ++stats_.tcp_bridges;
}

TcpBridge::~TcpBridge() {
    boost::system::error_code ec;
    socket_.close(ec);
    --stats_.tcp_bridges;
}

SecureChannel::Callbacks TcpBridge::callbacks() {
    auto self = shared_from_this();
    SecureChannel::Callbacks callbacks;
    callbacks.on_ready = [self] { self->do_tcp_read(); };
    callbacks.on_data = [self](std::vector<uint8_t>&& data) {
        if (self->closed_) {
            if (self->channel_) self->channel_->consumed_record();
            return;
        }
        self->write_queue_.push_back(std::move(data));
        self->do_tcp_write();
    };
    callbacks.on_fin = [self] {
        self->peer_fin_ = true;
        self->do_tcp_write();
    };
    callbacks.on_closed = [self](bool clean) { self->on_channel_closed(clean); };
    callbacks.on_writable = [self] {
        if (self->read_paused_ && !self->closed_) {
            self->read_paused_ = false;
            self->do_tcp_read();
        }
    };
    return callbacks;
}

void TcpBridge::connect_target(uint16_t port) {
    tcp::endpoint endpoint(boost::asio::ip::address_v4::loopback(), port);
    socket_.async_connect(endpoint, [this, self = shared_from_this(), port](boost::system::error_code ec) {
        if (closed_) return;
        if (ec) {
            logging::warn("[TCP] Не удалось подключиться к 127.0.0.1:", port, ": ", ec.message());
            close_tcp();
            if (channel_) channel_->abort();
            return;
        }
        tcp_ready_ = true;
        set_nodelay();
        do_tcp_write();
        do_tcp_read();
    });
}

void TcpBridge::set_nodelay() {
    boost::system::error_code ec;
    socket_.set_option(tcp::no_delay(true), ec);
}

void TcpBridge::do_tcp_read() {
    if (reading_ || closed_) return;
    reading_ = true;
    socket_.async_read_some(
        boost::asio::buffer(buffer_),
        [this, self = shared_from_this()](boost::system::error_code ec, std::size_t length) {
            reading_ = false;
            if (closed_) return;
            if (ec == boost::asio::error::eof) {
                if (channel_) channel_->finish();
                return;
            }
            if (ec || !channel_ || !channel_->send(buffer_.data(), length)) {
                close_tcp();
                if (channel_) channel_->abort();
                return;
            }
            // Возобновит on_writable: он приходит в io_context после этой проверки
            if (channel_->congested()) {
                read_paused_ = true;
                return;
            }
            do_tcp_read();
        }
    );
}

void TcpBridge::do_tcp_write() {
    if (!tcp_ready_ || writing_ || closed_) return;
    if (write_queue_.empty()) {
        if (channel_done_) {
            close_tcp();
        } else if (peer_fin_) {
            boost::system::error_code ec;
            socket_.shutdown(tcp::socket::shutdown_send, ec);
        }
        return;
    }
    writing_ = true;
    boost::asio::async_write(
        socket_,
        boost::asio::buffer(write_queue_.front()),
        [this, self = shared_from_this()](boost::system::error_code ec, std::size_t) {
            writing_ = false;
            if (closed_) return;
            if (ec) {
                close_tcp();
                if (channel_) channel_->abort();
                return;
            }
            write_queue_.pop_front();
            if (channel_) channel_->consumed_record();
            do_tcp_write();
        }
    );
}

void TcpBridge::close_tcp() {
    closed_ = true;
    boost::system::error_code ec;
    socket_.close(ec);
    write_queue_.clear();
}

void TcpBridge::on_channel_closed(bool clean) {
    channel_done_ = true;
    channel_.reset();
    if (!clean && peer_fin_ == false) {
        // Обрыв: программа должна увидеть ошибку, а не обычный конец данных
        boost::system::error_code ec;
        socket_.set_option(tcp::socket::linger(true, 0), ec);
        close_tcp();
        return;
    }
    if (write_queue_.empty() && !writing_) close_tcp();
}
