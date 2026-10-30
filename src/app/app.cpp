#include "app/app.hpp"

#include "core/log.hpp"

App::App(const NodeConfig& config, const identity::NetworkKeys& keys, const identity::NodeIdentity& self)
    : config_(config),
      quic_(keys.pkcs12),
      node_(std::make_unique<MeshNode>(io_, config_, stats_, keys, self)) {}

App::~App() {
    stop();
    node_.reset();
}

void App::start() {
    if (thread_.joinable()) return;
    io_.restart();
    thread_ = std::thread([this] {
        try {
            io_.run();
        } catch (const std::exception& e) {
            logging::error("[App] Сетевой поток остановлен: ", e.what());
        }
    });
}

void App::stop() {
    io_.stop();
    if (thread_.joinable()) thread_.join();
}

NodeStatus App::status() const {
    return node_->status();
}
