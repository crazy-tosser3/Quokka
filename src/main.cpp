#include "app/app.hpp"
#include "app/cli.hpp"
#include "core/identity.hpp"
#include "core/log.hpp"
#include "core/net_utils.hpp"
#include "core/routing.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

std::string services_text(const NodeConfig& config) {
    if (config.services.empty()) return "нет";
    std::string text;
    for (const Service& service : config.services) {
        if (!text.empty()) text += ", ";
        text += std::string(to_string(service.proto)) + " " + std::to_string(service.port);
    }
    return text;
}

std::string default_name() {
    char host[256]{};
    if (gethostname(host, sizeof(host) - 1) != 0) return {};
    std::string name(host);
    if (const auto dot = name.find('.'); dot != std::string::npos) name.resize(dot);
    if (name.size() > routing::MAX_NAME_SIZE) name.resize(routing::MAX_NAME_SIZE);
    return routing::is_valid_name(name) ? name : std::string{};
}

// up: сеть уже есть, если этот узел в неё входил; иначе создаём новую
identity::Invite prepare_up(const CliOptions& opts) {
    const auto dir = identity::state_dir();
    if (!opts.new_invite) {
        if (const auto saved = identity::load_saved_invite(dir)) return *saved;
    }
    const auto invite = identity::make_invite();
    identity::save_invite(dir, invite);
    return invite;
}

std::optional<identity::Invite> read_invite(const CliOptions& opts) {
    if (opts.invite) return identity::decode_invite(*opts.invite);
    if (const char* env = std::getenv("QUOKKA_INVITE"); env && *env) return identity::decode_invite(env);
    if (auto saved = identity::load_saved_invite(identity::state_dir())) return saved;
    if (!isatty(STDIN_FILENO)) return std::nullopt;

    std::cout << "Введите код приглашения: " << std::flush;
    std::string line;
    std::getline(std::cin, line);
    return identity::decode_invite(line);
}

identity::Invite prepare_join(const CliOptions& opts) {
    const auto invite = read_invite(opts);
    if (!invite) {
        throw std::runtime_error("Код приглашения не указан или повреждён. Скопируйте его целиком с любого узла сети.");
    }
    if (!opts.no_save) identity::save_invite(identity::state_dir(), *invite);
    return *invite;
}

void print_banner(const CliOptions& opts, const App& app, const identity::Invite& invite, const identity::NodeIdentity& self) {
    const auto& config = opts.config;
    std::string join_command = "quokka join " + identity::encode_invite(invite);
    for (const Service& service : config.services) {
        join_command += " --open " + std::to_string(service.port);
    }

    std::cout << "Quokka: узел " << (config.name.empty() ? "" : config.name + " ") << "(" << identity::short_id(self.id) << ")\n"
              << "  Свои сервисы: " << services_text(config) << "\n"
              << "  Входящие:     " << (config.max_listeners ? "до " + std::to_string(*config.max_listeners) : "без ограничений") << "\n"
              << "  QUIC-порт:    " << app.status().quic_port << "/udp\n\n"
              << "Чтобы добавить устройство в сеть, выполните на нём:\n\n"
              << "    " << join_command << "\n\n"
              << "Код — это пропуск в сеть: передавайте его только тем, кого хотите пустить.\n"
              << std::endl;
}

}

int main(int argc, char** argv) {
    CliOptions opts;
    try {
        opts = parse_cli(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n\nСправка: quokka --help\n";
        return 2;
    }
    if (opts.command == Command::Help) {
        std::cout << cli_usage();
        return 0;
    }
    if (opts.verbose) logging::set_min_level(logging::Level::Debug);

    try {
        const auto invite = opts.command == Command::Up ? prepare_up(opts) : prepare_join(opts);
        const auto self = identity::load_or_create_identity(identity::state_dir());
        if (opts.config.name.empty()) opts.config.name = default_name();
        raise_file_limit();

        App app(opts.config, identity::network_keys(invite), self);
        print_banner(opts, app, invite, self);
        app.start();

        boost::asio::io_context signals_io;
        boost::asio::signal_set signals(signals_io, SIGINT, SIGTERM);
        signals.async_wait([](const boost::system::error_code&, int) {});
        signals_io.run();

        logging::info("Завершаю работу...");
        app.stop();
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
