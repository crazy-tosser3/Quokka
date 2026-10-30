#pragma once

#include "core/config.hpp"
#include "core/identity.hpp"
#include "core/mesh_node.hpp"
#include "core/quic_runtime.hpp"
#include "core/stats.hpp"

#include <boost/asio/io_context.hpp>

#include <memory>
#include <thread>

class App {
public:
    App(const NodeConfig& config, const identity::NetworkKeys& keys, const identity::NodeIdentity& self);
    ~App();

    App(const App&) = delete;
    App& operator=(const App&) = delete;

    void start();
    void stop();
    bool running() const { return thread_.joinable(); }

    NodeStatus status() const;
    const NodeConfig& config() const { return config_; }

private:
    NodeConfig config_;
    Stats stats_;
    quic::Runtime quic_;
    boost::asio::io_context io_;
    std::unique_ptr<MeshNode> node_;
    std::thread thread_;
};
