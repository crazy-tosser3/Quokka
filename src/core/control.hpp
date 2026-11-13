#pragma once

#include <boost/asio.hpp>

#include <array>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>

// Управление работающим узлом с той же машины: quokka invite, quokka status.
// Unix-сокет с правами 0600 в папке ключей: обращаться может только владелец.
class ControlServer {
public:
    using Handler = std::function<std::string(const std::string& request)>;

    ControlServer(boost::asio::io_context& io, const std::filesystem::path& path, Handler handler);
    ~ControlServer();

private:
    void do_accept();

    boost::asio::local::stream_protocol::acceptor acceptor_;
    std::filesystem::path path_;
    Handler handler_;
};

// nullopt, если узел не запущен
std::optional<std::string> control_request(const std::filesystem::path& path, const std::string& request);
