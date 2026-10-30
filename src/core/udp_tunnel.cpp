#include "core/udp_tunnel.hpp"

#include "core/log.hpp"
#include "core/protocol.hpp"

#include <cstring>

namespace {

std::vector<uint8_t> make_packet(uint8_t type, uint8_t service, uint32_t flow_id,
                                 const uint8_t* data, std::size_t length) {
    std::vector<uint8_t> pkt(protocol::UDP_HEADER_SIZE + length);
    protocol::write_udp_header(pkt.data(), {type, service, flow_id});
    std::memcpy(pkt.data() + protocol::UDP_HEADER_SIZE, data, length);
    return pkt;
}

}

// --- Сервис пира на локальном порту ---

UdpClientEndpoint::UdpClientEndpoint(boost::asio::io_context& io, Stats& stats, uint8_t service,
                                     uint16_t local_port, DatagramSendFn send)
    : stats_(stats),
      service_(service),
      socket_(io, udp::endpoint(boost::asio::ip::address_v4::loopback(), local_port)),
      sweep_timer_(io),
      send_(std::move(send))
{
    do_receive();
    do_sweep();
}

UdpClientEndpoint::~UdpClientEndpoint() {
    stats_.udp_flows -= flows_.size();
}

uint16_t UdpClientEndpoint::local_port() const {
    return socket_.local_endpoint().port();
}

void UdpClientEndpoint::on_reply(uint32_t flow_id, const uint8_t* data, std::size_t length) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) return;
    it->second.last_active = Clock::now();
    auto payload = std::make_shared<std::vector<uint8_t>>(data, data + length);
    socket_.async_send_to(boost::asio::buffer(*payload), it->second.endpoint,
        [payload](boost::system::error_code, std::size_t) {});
}

void UdpClientEndpoint::do_receive() {
    socket_.async_receive_from(
        boost::asio::buffer(buffer_), sender_,
        [this](boost::system::error_code ec, std::size_t length) {
            if (ec == boost::asio::error::operation_aborted) return;
            if (!ec) {
                auto id = flow_ids_.find(sender_);
                if (id == flow_ids_.end() && flows_.size() < MAX_FLOWS) {
                    id = flow_ids_.emplace(sender_, next_flow_id_).first;
                    flows_[next_flow_id_] = {sender_, Clock::now()};
                    logging::debug("[UDP] Новый поток ", next_flow_id_, " от ", sender_);
                    ++next_flow_id_;
                    ++stats_.udp_flows;
                }
                if (id != flow_ids_.end()) {
                    flows_[id->second].last_active = Clock::now();
                    if (send_(make_packet(protocol::UDP_TO_TARGET, service_, id->second, buffer_.data(), length))) {
                        ++stats_.udp_packets_sent;
                    } else {
                        ++stats_.udp_packets_dropped;
                    }
                } else {
                    ++stats_.udp_packets_dropped;
                }
            }
            do_receive();
        }
    );
}

void UdpClientEndpoint::do_sweep() {
    sweep_timer_.expires_after(std::chrono::seconds(10));
    sweep_timer_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        const auto now = Clock::now();
        for (auto it = flows_.begin(); it != flows_.end();) {
            if (now - it->second.last_active > FLOW_IDLE_TIMEOUT) {
                flow_ids_.erase(it->second.endpoint);
                it = flows_.erase(it);
                --stats_.udp_flows;
            } else {
                ++it;
            }
        }
        do_sweep();
    });
}

// --- Свои сервисы ---

UdpTargetFlows::UdpTargetFlows(boost::asio::io_context& io, Stats& stats, DatagramSendFn send)
    : io_(io), stats_(stats), send_(std::move(send)), sweep_timer_(io)
{
    do_sweep();
}

UdpTargetFlows::~UdpTargetFlows() {
    for (auto& [key, flow] : flows_) close_flow(*flow);
}

void UdpTargetFlows::close_flow(Flow& flow) {
    boost::system::error_code ec;
    flow.socket.close(ec);
    --stats_.udp_flows;
}

void UdpTargetFlows::on_packet(uint8_t service, uint16_t target_port, uint32_t flow_id,
                               const uint8_t* data, std::size_t length) {
    ++stats_.udp_packets_received;
    const uint64_t key = (uint64_t(service) << 32) | flow_id;

    std::shared_ptr<Flow> flow;
    if (auto it = flows_.find(key); it != flows_.end()) {
        flow = it->second;
    } else {
        if (flows_.size() >= MAX_FLOWS) {
            ++stats_.udp_packets_dropped;
            return;
        }
        flow = open_flow(service, target_port, flow_id);
        if (!flow) {
            ++stats_.udp_packets_dropped;
            return;
        }
        flows_.emplace(key, flow);
        ++stats_.udp_flows;
    }

    flow->last_active = Clock::now();
    auto payload = std::make_shared<std::vector<uint8_t>>(data, data + length);
    flow->socket.async_send(boost::asio::buffer(*payload),
        [payload](boost::system::error_code, std::size_t) {});
}

std::shared_ptr<UdpTargetFlows::Flow> UdpTargetFlows::open_flow(uint8_t service, uint16_t target_port, uint32_t flow_id) {
    auto flow = std::make_shared<Flow>(io_);
    boost::system::error_code ec;
    flow->socket.connect(udp::endpoint(boost::asio::ip::address_v4::loopback(), target_port), ec);
    if (!ec) flow->socket.non_blocking(true, ec);
    if (ec) {
        logging::error("[UDP] Не удалось открыть сокет к порту ", target_port, ": ", ec.message());
        return nullptr;
    }
    logging::debug("[UDP] Поток ", flow_id, " -> 127.0.0.1:", target_port);
    do_receive(flow, service, flow_id);
    return flow;
}

void UdpTargetFlows::do_receive(const std::shared_ptr<Flow>& flow, uint8_t service, uint32_t flow_id) {
    flow->socket.async_wait(udp::socket::wait_read,
        [this, flow, service, flow_id](boost::system::error_code ec) {
            // Сокет закрывается раньше уничтожения UdpTargetFlows, поэтому до этой проверки this не трогаем
            if (ec == boost::asio::error::operation_aborted || !flow->socket.is_open()) return;
            if (!ec) {
                boost::system::error_code read_ec;
                const std::size_t length = flow->socket.receive(boost::asio::buffer(buffer_), 0, read_ec);
                if (!read_ec) {
                    flow->last_active = Clock::now();
                    if (send_(make_packet(protocol::UDP_REPLY, service, flow_id, buffer_.data(), length))) {
                        ++stats_.udp_packets_sent;
                    } else {
                        ++stats_.udp_packets_dropped;
                    }
                }
            }
            do_receive(flow, service, flow_id);
        });
}

void UdpTargetFlows::do_sweep() {
    sweep_timer_.expires_after(std::chrono::seconds(10));
    sweep_timer_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        const auto now = Clock::now();
        for (auto it = flows_.begin(); it != flows_.end();) {
            if (now - it->second->last_active > FLOW_IDLE_TIMEOUT) {
                close_flow(*it->second);
                it = flows_.erase(it);
            } else {
                ++it;
            }
        }
        do_sweep();
    });
}
