#include "app/app.hpp"

#include "core/log.hpp"

#include <cstdio>

namespace {

// Команды управляющего сокета. Запрос: "invite <секунды> <использований>" или "status"
std::string handle_control(MeshNode& node, const std::string& request) {
    if (request == "ping") return "ok\n";
    if (request == "status") return node.status_text();
    unsigned long seconds = 0;
    unsigned uses = 0;
    if (std::sscanf(request.c_str(), "invite %lu %u", &seconds, &uses) == 2 && seconds > 0 && uses > 0) {
        const auto invite = node.create_invite(std::chrono::seconds(seconds), uses);
        return invite.code + " " + std::to_string(seconds) + " " + std::to_string(uses) + " " + invite.host + "\n";
    }
    return "error\n";
}

}

App::App(const NodeConfig& config, const identity::Invite& network, const identity::NodeIdentity& self)
    : App(config, network, self, identity::network_keys(network)) {}

App::App(const NodeConfig& config, const identity::Invite& network, const identity::NodeIdentity& self,
         const identity::NetworkKeys& keys)
    : config_(config),
      quic_(keys.pkcs12, identity::make_pkcs12(identity::generate_identity().signing_seed)),
      node_(std::make_unique<MeshNode>(io_, config_, stats_, network, keys, self))
{
    control_ = std::make_unique<ControlServer>(io_, identity::state_dir() / "control.sock",
        [this](const std::string& request) { return handle_control(*node_, request); });
}

App::~App() {
    stop();
    control_.reset();
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
