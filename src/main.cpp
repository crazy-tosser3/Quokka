#include "app/app.hpp"
#include "app/cli.hpp"
#include "app/profiles.hpp"
#include "core/control.hpp"
#include "core/identity.hpp"
#include "core/log.hpp"
#include "core/net_utils.hpp"
#include "core/pairing.hpp"
#include "core/pake.hpp"
#include "core/routing.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

namespace {

constexpr auto DEFAULT_INVITE_TTL = std::chrono::minutes(15);
constexpr auto LAN_SEARCH_TIME = std::chrono::seconds(6);
constexpr int MAX_JOIN_ATTEMPTS = 3;
constexpr std::string_view DEFAULT_PROFILE = "default";

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

std::string ttl_text(std::chrono::seconds ttl) {
    if (ttl.count() % 3600 == 0) return std::to_string(ttl.count() / 3600) + " ч";
    if (ttl.count() % 60 == 0) return std::to_string(ttl.count() / 60) + " мин";
    return std::to_string(ttl.count()) + " с";
}

std::string invite_text(const std::string& code, std::chrono::seconds ttl, unsigned uses, const std::string& host,
                        const NodeConfig& config) {
    std::string command = "quokka join " + code;
    if (!host.empty()) command += " --peer " + host;
    for (const Service& service : config.services) command += " --open " + std::to_string(service.port);

    std::ostringstream out;
    out << "Код приглашения: " << code << "  (действует " << ttl_text(ttl) << ", устройств: " << uses << ")\n\n"
        << "На новом устройстве выполните:\n\n"
        << "    " << command << "\n\n";
    if (host.empty()) {
        out << "Без --peer устройство найдёт узел только в локальной сети. Если он доступен извне,\n"
               "запустите его с --public АДРЕС, чтобы адрес подставлялся сам.\n\n";
    }
    return out.str();
}

// --- Какую сеть запускать ---

struct Selected {
    identity::Invite network;
    NodeConfig config;
    bool created = false;
    std::string profile;
};

identity::Invite decode_saved(const Profile& profile) {
    const auto invite = identity::decode_invite(profile.code);
    if (!invite) throw std::runtime_error("Ключ сети в файле настроек повреждён");
    return *invite;
}

Selected select_up(const CliOptions& opts) {
    auto file = load_profiles();
    std::string name = opts.profile;
    if (name.empty()) name = file.default_name.empty() ? std::string(DEFAULT_PROFILE) : file.default_name;

    Selected selected;
    selected.profile = name;
    selected.config = opts.config;
    const auto existing = file.profiles.find(name);
    if (existing != file.profiles.end() && !opts.new_invite) {
        selected.network = decode_saved(existing->second);
        if (!opts.profile.empty()) save_profile(name, Profile{identity::encode_invite(selected.network), opts.config}, false);
    } else {
        selected.network = identity::make_invite();
        selected.created = true;
        save_profile(name, Profile{identity::encode_invite(selected.network), opts.config},
                     file.default_name.empty() || file.default_name == name);
    }
    return selected;
}

std::string read_code_interactively() {
    if (!isatty(STDIN_FILENO)) return {};
    std::cout << "Введите код приглашения: " << std::flush;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

// Короткий код меняем на настоящий ключ сети: сначала у указанных адресов, затем в локальной сети
identity::Invite pair_with_code(const std::string& code, const NodeConfig& config) {
    std::vector<pairing::LanHost> hosts;
    for (const PeerAddress& peer : config.peers) hosts.push_back({peer.host, peer.port});

    int wrong = 0;
    const auto try_host = [&](const pairing::LanHost& host) -> std::optional<identity::Invite> {
        std::cout << "Вход через " << host.host << ":" << host.port << "..." << std::endl;
        const auto outcome = pairing::join(host.host, host.port, code);
        if (outcome.result == pairing::Result::Ok && outcome.invite) return outcome.invite;
        if (outcome.result == pairing::Result::WrongCode) ++wrong;
        return std::nullopt;
    };

    for (const auto& host : hosts) {
        if (wrong >= MAX_JOIN_ATTEMPTS) break;
        if (auto invite = try_host(host)) return *invite;
    }
    if (config.discovery && wrong < MAX_JOIN_ATTEMPTS) {
        std::cout << "Ищу узел с кодом в локальной сети..." << std::endl;
        for (const auto& host : pairing::find_on_lan(config.multicast_ip, config.discovery_port, LAN_SEARCH_TIME)) {
            if (wrong >= MAX_JOIN_ATTEMPTS) break;
            if (auto invite = try_host(host)) return *invite;
        }
    }

    if (wrong > 0) {
        throw std::runtime_error("Код не подошёл: он неверный, уже использован или истёк. Попросите новый: quokka invite");
    }
    if (config.peers.empty()) {
        throw std::runtime_error("Не нашёл узел с кодом в локальной сети. Если он в другой сети, укажите адрес: --peer АДРЕС");
    }
    throw std::runtime_error("Узел недоступен, или код уже использован или истёк. Проверьте адрес и UDP-порт 30002, "
                             "при необходимости запросите новый код: quokka invite");
}

Selected select_join(const CliOptions& opts) {
    std::string text = opts.invite.value_or("");
    if (text.empty()) {
        if (const char* env = std::getenv("QUOKKA_INVITE"); env && *env) text = env;
    }
    if (text.empty()) text = read_code_interactively();
    if (text.empty()) throw std::runtime_error("Код приглашения не указан. Его можно получить на любом узле: quokka invite");

    Selected selected;
    selected.config = opts.config;
    if (const auto code = pake::normalize_code(text)) {
        selected.network = pair_with_code(*code, opts.config);
    } else if (const auto full = identity::decode_invite(text)) {
        selected.network = *full;
    } else {
        throw std::runtime_error("Код приглашения повреждён: проверьте опечатки. Он выглядит как ABC-DEF-GHJ");
    }
    if (opts.no_save) return selected;

    // Запоминаем сеть, чтобы дальше хватало команды quokka
    const auto file = load_profiles();
    const std::string code_text = identity::encode_invite(selected.network);
    std::string name = opts.profile;
    if (name.empty()) {
        for (const auto& [existing, profile] : file.profiles) {
            if (profile.code == code_text) name = existing;
        }
    }
    if (name.empty()) {
        name = std::string(DEFAULT_PROFILE);
        for (int i = 2; file.profiles.contains(name); ++i) name = "network" + std::to_string(i);
    }
    selected.profile = name;
    const auto existing = file.profiles.find(name);
    if (opts.profile.empty() && existing != file.profiles.end() && existing->second.code == code_text) {
        return selected;  // уже сохранена: настройки меняются только явно через --save
    }
    save_profile(name, Profile{code_text, opts.config}, file.default_name.empty());
    std::cout << "Сеть сохранена как '" << name << "'. В следующий раз хватит команды: quokka connect " << name << std::endl;
    return selected;
}

Selected select_saved(const std::string& name, const NodeConfig& config) {
    const auto file = load_profiles();
    const auto it = file.profiles.find(name);
    if (it == file.profiles.end()) throw std::runtime_error("Сети '" + name + "' нет. Посмотреть список: quokka list");
    return Selected{decode_saved(it->second), config, false, name};
}

// quokka без аргументов: одна сеть запускается сразу, из нескольких можно выбрать
std::string choose_profile() {
    const auto file = load_profiles();
    if (file.profiles.empty()) return {};
    if (file.profiles.size() == 1) return file.profiles.begin()->first;
    if (!isatty(STDIN_FILENO)) {
        if (!file.default_name.empty()) return file.default_name;
        throw std::runtime_error("Сетей несколько: укажите нужную, quokka connect ИМЯ");
    }

    std::cout << "Сети:\n";
    std::vector<std::string> names;
    for (const auto& [name, profile] : file.profiles) {
        names.push_back(name);
        std::cout << "  " << names.size() << ") " << name << (name == file.default_name ? " (по умолчанию)" : "");
        if (!profile.config.peers.empty()) std::cout << "  через " << profile.config.peers.front().host;
        std::cout << "\n";
    }
    std::cout << "Куда подключиться? [" << (file.default_name.empty() ? "1" : file.default_name) << "]: " << std::flush;
    std::string line;
    std::getline(std::cin, line);
    if (line.empty()) return file.default_name.empty() ? names.front() : file.default_name;
    if (file.profiles.contains(line)) return line;
    const std::size_t index = static_cast<std::size_t>(std::atoi(line.c_str()));
    if (index < 1 || index > names.size()) throw std::runtime_error("Нет такой сети");
    return names[index - 1];
}

void print_list() {
    const auto file = load_profiles();
    std::cout << "Файл настроек: " << config_path().string() << "\n\n";
    if (file.profiles.empty()) {
        std::cout << "Сохранённых сетей нет. Создать: quokka up. Войти: quokka join КОД\n";
        return;
    }
    for (const auto& [name, profile] : file.profiles) {
        const NodeConfig& c = profile.config;
        std::cout << name << (name == file.default_name ? " (по умолчанию)" : "") << "\n";
        if (!c.name.empty()) std::cout << "  имя узла:  " << c.name << "\n";
        for (const PeerAddress& peer : c.peers) std::cout << "  сосед:     " << peer.host << ":" << peer.port << "\n";
        if (!c.services.empty()) std::cout << "  сервисы:   " << services_text(c) << "\n";
        for (const OpenRule& rule : c.open_rules) {
            std::cout << "  открывает: " << (rule.port == 0 ? "все сервисы" : (rule.node.empty() ? "" : rule.node + ":") + std::to_string(rule.port));
            if (rule.local_port != 0) std::cout << " на порту " << rule.local_port;
            std::cout << "\n";
        }
        if (!c.relay) std::cout << "  транзит:   выключен\n";
        if (!c.discovery) std::cout << "  автопоиск: выключен\n";
    }
}

// --- Команды для работающего узла ---

int run_invite(const CliOptions& opts) {
    if (opts.invite_full) {
        const auto file = load_profiles();
        const auto it = file.profiles.find(file.default_name);
        if (it == file.profiles.end()) throw std::runtime_error("Сохранённых сетей нет");
        std::cout << it->second.code << std::endl;
        return 0;
    }
    std::ostringstream request;
    request << "invite " << opts.invite_ttl.count() << " " << opts.invite_uses;
    const auto response = control_request(identity::state_dir() / "control.sock", request.str());
    if (!response) throw std::runtime_error("Узел не запущен: код выдаёт работающий узел. Запустите quokka up");

    std::istringstream parts(*response);
    std::string code, host;
    unsigned long seconds = 0;
    unsigned uses = 0;
    parts >> code >> seconds >> uses >> host;
    if (code == "error" || code.empty()) throw std::runtime_error("Не удалось выдать код");
    std::cout << invite_text(code, std::chrono::seconds(seconds), uses, host, NodeConfig{}) << std::flush;
    return 0;
}

int run_status() {
    const auto response = control_request(identity::state_dir() / "control.sock", "status");
    if (!response) {
        std::cerr << "Узел не запущен\n";
        return 1;
    }
    std::cout << *response;
    return 0;
}

void print_banner(const NodeConfig& config, App& app, const identity::NodeIdentity& self, const Selected& selected, bool issue_code) {
    std::ostringstream out;
    out << "Quokka: узел " << (config.name.empty() ? "" : config.name + " ") << "(" << identity::short_id(self.id) << ")\n"
        << "  Сеть:         " << (selected.profile.empty() ? "без сохранения" : selected.profile) << "\n"
        << "  Свои сервисы: " << services_text(config) << "\n"
        << "  Входящие:     " << (config.max_listeners ? "до " + std::to_string(*config.max_listeners) : "без ограничений") << "\n"
        << "  Транзит:      " << (config.relay ? "да" : "нет") << "\n"
        << "  QUIC-порт:    " << app.status().quic_port << "/udp\n";
    if (!config.public_address.empty()) out << "  Адрес:        " << config.public_address << "\n";
    out << "\n";

    if (issue_code) {
        const auto invite = app.node().create_invite(DEFAULT_INVITE_TTL, 1);
        out << invite_text(invite.code, invite.ttl, invite.uses, invite.host, config);
    } else {
        out << "Добавить устройство: quokka invite\n";
    }
    // Узел уже принимает соединения, и лог могут писать другие потоки
    logging::info(out.str());
}

}

int main(int argc, char** argv) {
    CliOptions opts;
    try {
        const ProfileLoader loader = [](const std::string& requested) -> std::optional<NodeConfig> {
            const auto file = load_profiles();
            const std::string name = requested.empty() ? file.default_name : requested;
            const auto it = file.profiles.find(name);
            if (it == file.profiles.end()) return std::nullopt;
            return it->second.config;
        };
        opts = parse_cli(argc, argv, loader);
    } catch (const std::invalid_argument& e) {
        std::cerr << e.what() << "\n\nСправка: quokka --help\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    if (opts.command == Command::Help) {
        std::cout << cli_usage();
        return 0;
    }
    if (opts.verbose) logging::set_min_level(logging::Level::Debug);

    try {
        Selected selected;
        switch (opts.command) {
        case Command::List:
            print_list();
            return 0;
        case Command::Invite:
            return run_invite(opts);
        case Command::Status:
            return run_status();
        case Command::Menu: {
            const std::string name = choose_profile();
            if (name.empty()) {
                std::cout << cli_usage();
                return 0;
            }
            selected = select_saved(name, load_profiles().profiles.at(name).config);
            break;
        }
        case Command::Connect:
            selected = select_saved(opts.profile, opts.config);
            break;
        case Command::Join:
            selected = select_join(opts);
            break;
        default:
            selected = select_up(opts);
            break;
        }

        const auto self = identity::load_or_create_identity(identity::state_dir());
        if (selected.config.name.empty()) selected.config.name = default_name();
        raise_file_limit();

        App app(selected.config, selected.network, self);
        print_banner(selected.config, app, self, selected, selected.created);
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
