#pragma once

#include "core/aead.hpp"
#include "core/protocol.hpp"

#include <boost/asio.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>

// Маяк: узел раз в 2 секунды сообщает в локальную сеть, что он здесь.
// Маяк лишь подсказывает адрес. Подлинность соседа проверяется при рукопожатии,
// поэтому поддельный или повторённый маяк не даёт злоумышленнику доступа.
class BeaconSender {
public:
    BeaconSender(boost::asio::io_context& io, const std::string& multicast_ip, uint16_t discovery_port,
                 const protocol::Beacon& beacon, const Aead::Key& key);

private:
    void do_send();

    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint group_;
    boost::asio::steady_timer timer_;
    Aead aead_;
    protocol::Beacon beacon_;
};

class BeaconReceiver {
public:
    using FoundFn = std::function<void(const boost::asio::ip::address&, const protocol::Beacon&)>;

    BeaconReceiver(boost::asio::io_context& io, const std::string& multicast_ip, uint16_t discovery_port,
                   const Aead::Key& key, FoundFn found);

private:
    void do_receive();
    void do_join();

    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::address group_;
    boost::asio::ip::udp::endpoint sender_;
    std::array<unsigned char, 512> buffer_{};
    boost::asio::steady_timer join_timer_;
    Aead aead_;
    FoundFn found_;
};
