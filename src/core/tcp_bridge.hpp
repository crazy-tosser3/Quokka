#pragma once

#include "core/secure_channel.hpp"
#include "core/stats.hpp"

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

// Одно TCP-подключение, идущее через сквозной канал.
class TcpBridge : public std::enable_shared_from_this<TcpBridge> {
public:
    using tcp = boost::asio::ip::tcp;

    TcpBridge(boost::asio::io_context& io, Stats& stats, tcp::socket socket);
    explicit TcpBridge(boost::asio::io_context& io, Stats& stats);
    ~TcpBridge();

    // Обработчики для канала. Нужно передать их в SecureChannel до прихода данных.
    SecureChannel::Callbacks callbacks();
    void set_channel(SecureChannel::Ref channel) { channel_ = std::move(channel); }

    // Сторона сервиса: подключиться к 127.0.0.1:port
    void connect_target(uint16_t port);

private:
    void set_nodelay();
    void do_tcp_read();
    void do_tcp_write();
    void close_tcp();
    void on_channel_closed(bool clean);

    Stats& stats_;
    tcp::socket socket_;
    std::array<char, 16384> buffer_{};
    SecureChannel::Ref channel_;
    std::deque<std::vector<uint8_t>> write_queue_;

    bool tcp_ready_{false};
    bool writing_{false};
    bool peer_fin_{false};
    bool read_paused_{false};
    bool reading_{false};
    bool channel_done_{false};
    bool closed_{false};
};
