#include "core/control.hpp"

#include "core/log.hpp"

#include <sys/stat.h>
#include <unistd.h>

using boost::asio::local::stream_protocol;

namespace {

constexpr std::size_t MAX_REQUEST = 256;

class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(stream_protocol::socket socket, const ControlServer::Handler& handler)
        : socket_(std::move(socket)), handler_(handler) {}

    void start() {
        boost::asio::async_read_until(socket_, boost::asio::dynamic_buffer(request_, MAX_REQUEST), '\n',
            [self = shared_from_this()](boost::system::error_code ec, std::size_t) {
                if (ec) return;
                self->request_.pop_back();
                self->response_ = self->handler_(self->request_);
                boost::asio::async_write(self->socket_, boost::asio::buffer(self->response_),
                    [self](boost::system::error_code, std::size_t) {});
            });
    }

private:
    stream_protocol::socket socket_;
    const ControlServer::Handler& handler_;
    std::string request_;
    std::string response_;
};

}

ControlServer::ControlServer(boost::asio::io_context& io, const std::filesystem::path& path, Handler handler)
    : acceptor_(io), path_(path), handler_(std::move(handler))
{
    // Если узел с этой папкой уже работает, сокет трогать нельзя; если он умер, сокет остался от него
    if (control_request(path_, "ping")) {
        path_.clear();
        logging::warn("[Управление] В этой папке уже работает другой узел: quokka invite и status обратятся к нему");
        return;
    }
    ::unlink(path_.c_str());

    const mode_t previous = ::umask(077);  // сокет не должен быть доступен ни на мгновение
    boost::system::error_code ec;
    acceptor_.open(stream_protocol(), ec);
    if (!ec) acceptor_.bind(stream_protocol::endpoint(path_.string()), ec);
    if (!ec) acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    ::umask(previous);
    if (ec) {
        path_.clear();
        logging::warn("[Управление] Не удалось открыть сокет: ", ec.message(), ". quokka invite и status работать не будут");
        return;
    }
    do_accept();
}

ControlServer::~ControlServer() {
    boost::system::error_code ec;
    acceptor_.close(ec);
    if (!path_.empty()) ::unlink(path_.c_str());
}

void ControlServer::do_accept() {
    acceptor_.async_accept([this](boost::system::error_code ec, stream_protocol::socket socket) {
        if (ec == boost::asio::error::operation_aborted) return;
        if (!ec) std::make_shared<Connection>(std::move(socket), handler_)->start();
        do_accept();
    });
}

std::optional<std::string> control_request(const std::filesystem::path& path, const std::string& request) {
    boost::asio::io_context io;
    stream_protocol::socket socket(io);
    boost::system::error_code ec;
    socket.connect(stream_protocol::endpoint(path.string()), ec);
    if (ec) return std::nullopt;
    boost::asio::write(socket, boost::asio::buffer(request + "\n"), ec);
    if (ec) return std::nullopt;
    std::string response;
    boost::asio::read(socket, boost::asio::dynamic_buffer(response), ec);
    return response;
}
