#pragma once

#include "core/stats.hpp"

#include <boost/asio.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

using DatagramSendFn = std::function<bool(std::vector<uint8_t>&&)>;

// Локальный UDP-порт одного сервиса пира. Каждому адресу отправителя (игре на этой машине)
// выделяется свой flow, чтобы у владельца сервиса он получил свой сокет.
class UdpClientEndpoint {
public:
    using udp = boost::asio::ip::udp;

    // local_port = 0: выбрать свободный. Бросает boost::system::system_error, если порт занят
    UdpClientEndpoint(boost::asio::io_context& io, Stats& stats, uint8_t service,
                      uint16_t local_port, DatagramSendFn send);
    ~UdpClientEndpoint();

    uint16_t local_port() const;
    void on_reply(uint32_t flow_id, const uint8_t* data, std::size_t length);

private:
    using Clock = std::chrono::steady_clock;
    static constexpr std::size_t MAX_FLOWS = 4096;
    static constexpr auto FLOW_IDLE_TIMEOUT = std::chrono::seconds(60);

    struct Flow {
        udp::endpoint endpoint;
        Clock::time_point last_active;
    };

    void do_receive();
    void do_sweep();

    Stats& stats_;
    uint8_t service_;
    udp::socket socket_;
    udp::endpoint sender_;
    std::array<uint8_t, 65536> buffer_{};
    boost::asio::steady_timer sweep_timer_;
    DatagramSendFn send_;

    std::map<udp::endpoint, uint32_t> flow_ids_;
    std::unordered_map<uint32_t, Flow> flows_;
    uint32_t next_flow_id_{1};
};

// Свои UDP-сервисы, по одному объекту на подключённого пира: для каждого flow — свой сокет
// к целевому порту, поэтому игровой сервер видит устройства как отдельных клиентов.
class UdpTargetFlows {
public:
    using udp = boost::asio::ip::udp;

    UdpTargetFlows(boost::asio::io_context& io, Stats& stats, DatagramSendFn send);
    ~UdpTargetFlows();

    void on_packet(uint8_t service, uint16_t target_port, uint32_t flow_id,
                   const uint8_t* data, std::size_t length);

private:
    using Clock = std::chrono::steady_clock;
    // Предел на устройство: с разрешением пира нельзя исчерпать дескрипторы всего сервера
    static constexpr std::size_t MAX_FLOWS = 1024;
    static constexpr auto FLOW_IDLE_TIMEOUT = std::chrono::seconds(60);

    struct Flow {
        explicit Flow(boost::asio::io_context& io) : socket(io) {}
        udp::socket socket;
        Clock::time_point last_active;
    };

    std::shared_ptr<Flow> open_flow(uint8_t service, uint16_t target_port, uint32_t flow_id);
    void do_receive(const std::shared_ptr<Flow>& flow, uint8_t service, uint32_t flow_id);
    void do_sweep();
    void close_flow(Flow& flow);

    boost::asio::io_context& io_;
    Stats& stats_;
    DatagramSendFn send_;
    boost::asio::steady_timer sweep_timer_;
    // Сокетов может быть много, поэтому общий буфер: данные читаются только когда уже готовы
    std::array<uint8_t, 65536> buffer_{};
    std::unordered_map<uint64_t, std::shared_ptr<Flow>> flows_;  // (service << 32) | flow_id
};
