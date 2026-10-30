#include "app/cli.hpp"

#include "core/routing.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace {

unsigned long long parse_number(std::string_view name, std::string_view value, unsigned long long max) {
    unsigned long long number = 0;
    auto [ptr, err] = std::from_chars(value.data(), value.data() + value.size(), number);
    if (err != std::errc{} || ptr != value.data() + value.size() || number == 0 || number > max) {
        throw std::invalid_argument(std::string(name) + ": неверное значение '" + std::string(value) + "'");
    }
    return number;
}

uint16_t parse_port(std::string_view name, std::string_view value) {
    return static_cast<uint16_t>(parse_number(name, value, 65535));
}

void add_service(NodeConfig& config, ServiceProto proto, uint16_t port) {
    const Service service{proto, port};
    if (std::find(config.services.begin(), config.services.end(), service) != config.services.end()) return;
    if (config.services.size() >= MAX_SERVICES) {
        throw std::invalid_argument("Слишком много сервисов, максимум " + std::to_string(MAX_SERVICES));
    }
    config.services.push_back(service);
}

void parse_peer(NodeConfig& config, std::string_view value) {
    PeerAddress peer;
    const auto colon = value.rfind(':');
    if (colon == std::string_view::npos) {
        peer.host = value;
    } else {
        peer.host = value.substr(0, colon);
        peer.port = parse_port("--peer", value.substr(colon + 1));
    }
    if (peer.host.empty()) throw std::invalid_argument("--peer: не указан адрес");
    config.peers.push_back(std::move(peer));
}

// [УЗЕЛ:]ПОРТ[=ЛОКАЛЬНЫЙ] или all
void parse_open(NodeConfig& config, std::string_view value) {
    OpenRule rule;
    if (value != "all") {
        if (const auto eq = value.find('='); eq != std::string_view::npos) {
            rule.local_port = parse_port("--open", value.substr(eq + 1));
            value = value.substr(0, eq);
        }
        if (const auto colon = value.rfind(':'); colon != std::string_view::npos) {
            rule.node = value.substr(0, colon);
            value = value.substr(colon + 1);
            if (rule.node.empty()) throw std::invalid_argument("--open: не указан узел");
        }
        rule.port = parse_port("--open", value);
    }
    config.open_rules.push_back(std::move(rule));
}

}

std::string cli_usage() {
    return R"(Quokka — защищённая mesh-сеть для игр и программ.

Все узлы равны: каждый может открывать свои порты, пользоваться чужими
и передавать трафик других узлов. Соседи находятся автоматически.

Использование:
  quokka up [опции]             запустить узел; при первом запуске создаёт сеть и код
  quokka join [КОД] [опции]     войти в сеть по коду

Сервисы:
  --udp ПОРТ             открыть сети UDP-порт этой машины (можно несколько раз)
  --tcp ПОРТ             открыть сети TCP-порт этой машины (можно несколько раз)
  --open ПОРТ            открыть сервис сети на этой машине: 127.0.0.1:ПОРТ
  --open ПОРТ=ЛОКАЛЬНЫЙ  то же, на другом локальном порту
  --open УЗЕЛ:ПОРТ       сервис конкретного узла (имя или начало идентификатора)
  --open all             открыть все сервисы сети

Сеть:
  --peer IP[:ПОРТ]       подключаться к этому адресу (можно несколько раз)
  --no-discovery         не искать соседей автоматически
  --listeners N          максимум входящих соединений (по умолчанию без ограничений)
  --port ПОРТ            UDP-порт QUIC (по умолчанию 30002; занят — выбирается свободный)
  --name ИМЯ             имя узла (по умолчанию имя машины)
  --discovery-port ПОРТ  UDP-порт автопоиска (по умолчанию 30001)
  --multicast-ip IP      группа автопоиска (по умолчанию 239.255.0.1)

Прочее:
  КОД                    код приглашения; без него берётся сохранённый или запрашивается
  --new-invite           up: создать новую сеть с новым кодом
  --no-save              join: не запоминать код на этой машине
  -v, --verbose          подробный лог
  -h, --help             эта справка

Пример:
  quokka up --tcp 8000
  quokka join quokka2abc... --open 8000
)";
}

CliOptions parse_cli(int argc, char** argv) {
    CliOptions opts;
    NodeConfig& c = opts.config;

    if (argc < 2) return opts;
    const std::string_view command = argv[1];
    if (command == "up") {
        opts.command = Command::Up;
    } else if (command == "join") {
        opts.command = Command::Join;
    } else if (command == "-h" || command == "--help" || command == "help") {
        return opts;
    } else {
        throw std::invalid_argument("Неизвестная команда '" + std::string(command) + "'");
    }
    const bool is_join = opts.command == Command::Join;

    for (int i = 2; i < argc; ++i) {
        const std::string_view arg = argv[i];
        auto value = [&]() -> std::string_view {
            if (i + 1 >= argc) throw std::invalid_argument(std::string(arg) + ": нужно значение");
            return argv[++i];
        };

        if (arg == "-h" || arg == "--help") {
            opts.command = Command::Help;
            return opts;
        }
        else if (arg == "-v" || arg == "--verbose")  opts.verbose = true;
        else if (arg == "--udp")                     add_service(c, ServiceProto::Udp, parse_port(arg, value()));
        else if (arg == "--tcp")                     add_service(c, ServiceProto::Tcp, parse_port(arg, value()));
        else if (arg == "--open")                    parse_open(c, value());
        else if (arg == "--peer")                    parse_peer(c, value());
        else if (arg == "--no-discovery")            c.discovery = false;
        else if (arg == "--discovery-port")          c.discovery_port = parse_port(arg, value());
        else if (arg == "--multicast-ip")            c.multicast_ip = value();
        else if (arg == "--name")                    c.name = value();
        else if (arg == "--port") {
            c.quic_port = parse_port(arg, value());
            c.quic_port_explicit = true;
        }
        else if (arg == "--listeners") {
            c.max_listeners = parse_number(arg, value(), std::numeric_limits<std::size_t>::max());
        }
        else if (!is_join && arg == "--new-invite")  opts.new_invite = true;
        else if (is_join && arg == "--no-save")      opts.no_save = true;
        else if (is_join && !arg.starts_with("-") && !opts.invite) {
            opts.invite = std::string(arg);
            std::memset(argv[i], 'x', arg.size());
        }
        else throw std::invalid_argument("Неизвестный аргумент '" + std::string(arg) + "'");
    }

    if (!routing::is_valid_name(c.name)) {
        throw std::invalid_argument("--name: не длиннее " + std::to_string(routing::MAX_NAME_SIZE) +
                                    " байт и без управляющих символов");
    }
    return opts;
}
