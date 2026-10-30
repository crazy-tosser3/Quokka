#include "core/discovery.hpp"

#include "core/log.hpp"
#include "core/net_utils.hpp"
#include "core/protocol.hpp"

#include <sys/socket.h>

using boost::asio::ip::udp;

BeaconSender::BeaconSender(boost::asio::io_context& io, const std::string& multicast_ip,
                           uint16_t discovery_port, const protocol::Beacon& beacon, const Aead::Key& key)
    : socket_(io, udp::v4()),
      group_(boost::asio::ip::make_address(multicast_ip), discovery_port),
      timer_(io),
      aead_(key),
      beacon_(beacon)
{
    // Пакеты должны доходить и до других узлов на этой же машине
    socket_.set_option(boost::asio::ip::multicast::enable_loopback(true));
    do_send();
}

void BeaconSender::do_send() {
    const auto packet = aead_.encrypt(protocol::encode_beacon(beacon_));
    for (const auto& iface : local_ipv4_interfaces()) {
        boost::system::error_code ec;
        socket_.set_option(boost::asio::ip::multicast::outbound_interface(iface), ec);
        if (!ec) socket_.send_to(boost::asio::buffer(packet), group_, 0, ec);
        if (ec) logging::debug("[Поиск] Не удалось отправить маяк через ", iface, ": ", ec.message());
    }

    timer_.expires_after(std::chrono::seconds(2));
    timer_.async_wait([this](boost::system::error_code ec) {
        if (!ec) do_send();
    });
}

BeaconReceiver::BeaconReceiver(boost::asio::io_context& io, const std::string& multicast_ip,
                               uint16_t discovery_port, const Aead::Key& key, FoundFn found)
    : socket_(io),
      group_(boost::asio::ip::make_address(multicast_ip)),
      join_timer_(io),
      aead_(key),
      found_(std::move(found))
{
    const udp::endpoint endpoint(boost::asio::ip::address_v4::any(), discovery_port);
    socket_.open(endpoint.protocol());
    socket_.set_option(udp::socket::reuse_address(true));
    // Несколько узлов на одной машине должны получать один и тот же маяк
    const int one = 1;
    setsockopt(socket_.native_handle(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    socket_.bind(endpoint);
    do_join();
    do_receive();
}

// Повторяется по таймеру: сеть могла появиться или смениться (Wi-Fi, VPN, сон ноутбука)
void BeaconReceiver::do_join() {
    for (const auto& iface : local_ipv4_interfaces()) {
        boost::system::error_code ignored;  // "уже присоединились" — не ошибка
        socket_.set_option(boost::asio::ip::multicast::join_group(group_.to_v4(), iface), ignored);
    }
    join_timer_.expires_after(std::chrono::seconds(10));
    join_timer_.async_wait([this](boost::system::error_code ec) {
        if (!ec) do_join();
    });
}

void BeaconReceiver::do_receive() {
    socket_.async_receive_from(
        boost::asio::buffer(buffer_), sender_,
        [this](boost::system::error_code ec, std::size_t length) {
            if (ec == boost::asio::error::operation_aborted) return;
            if (!ec) {
                // Чужие пакеты молча отбрасываем: в одной сети может работать много независимых сетей Quokka
                std::string plaintext;
                if (aead_.decrypt(buffer_.data(), length, plaintext)) {
                    if (const auto beacon = protocol::decode_beacon(plaintext)) {
                        found_(sender_.address(), *beacon);
                    }
                }
            }
            do_receive();
        }
    );
}
