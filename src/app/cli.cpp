#include "app/cli.hpp"

#include "app/profiles.hpp"
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

// 90s, 15m, 2h или просто минуты
std::chrono::seconds parse_duration(std::string_view name, std::string_view value) {
    unsigned long long unit = 60;
    if (!value.empty()) {
        const char suffix = value.back();
        if (suffix == 's') unit = 1;
        else if (suffix == 'm') unit = 60;
        else if (suffix == 'h') unit = 3600;
        if (suffix < '0' || suffix > '9') value.remove_suffix(1);
    }
    const auto seconds = parse_number(name, value, 24 * 3600) * unit;
    if (seconds > 24 * 3600) throw std::invalid_argument(std::string(name) + ": не больше суток");
    return std::chrono::seconds(seconds);
}

void parse_public(NodeConfig& config, std::string_view value) {
    if (value.empty() || value.size() > routing::MAX_NAME_SIZE * 2 ||
        !std::all_of(value.begin(), value.end(), [](char c) { return c > 0x20 && c < 0x7F; })) {
        throw std::invalid_argument("--public: нужен адрес вида vps.example.com или 203.0.113.5");
    }
    config.public_address = value;
}

}

std::string cli_usage() {
    return R"(Quokka — защищённая mesh-сеть для игр и программ.

Все узлы равны: каждый может открывать свои порты, пользоваться чужими
и передавать трафик других узлов. Соседи в локальной сети находятся автоматически.

Команды:
  quokka                    выбрать сеть из сохранённых и подключиться
  quokka up [опции]         запустить узел; при первом запуске создаёт сеть
  quokka server [опции]     запустить узел на VPS: через него видят друг друга машины за NAT
  quokka join КОД [опции]   войти в сеть по коду вида ABC-DEF-GHJ
  quokka connect ИМЯ [опции]  подключиться к сохранённой сети
  quokka invite             выдать код приглашения (узел должен быть запущен)
  quokka status             показать состояние запущенного узла
  quokka list               показать сохранённые сети

Сервисы:
  --udp ПОРТ             открыть сети UDP-порт этой машины (можно несколько раз)
  --tcp ПОРТ             открыть сети TCP-порт этой машины (можно несколько раз)
  --open ПОРТ            открыть сервис сети на этой машине: 127.0.0.1:ПОРТ
  --open ПОРТ=ЛОКАЛЬНЫЙ  то же, на другом локальном порту
  --open УЗЕЛ:ПОРТ       сервис конкретного узла (имя или начало идентификатора)
  --open all             открыть все сервисы сети

Сеть:
  --peer АДРЕС[:ПОРТ]    всегда подключаться к этому адресу (можно несколько раз)
  --public АДРЕС         адрес, по которому этот узел доступен извне
  --no-discovery         не искать соседей автоматически
  --no-relay             не передавать чужой трафик
  --listeners N          максимум входящих соединений (по умолчанию без ограничений)
  --port ПОРТ            UDP-порт QUIC (по умолчанию 30002; занят — выбирается свободный)
  --name ИМЯ             имя узла (по умолчанию имя машины)
  --discovery-port ПОРТ  UDP-порт автопоиска (по умолчанию 30001)
  --multicast-ip IP      группа автопоиска (по умолчанию 239.255.0.1)

Сохранение:
  --save ИМЯ             сохранить настройки в config.toml под этим именем
  --no-save              join: ничего не сохранять
  --new-invite           up: создать новую сеть вместо сохранённой

Приглашения (quokka invite):
  --ttl ВРЕМЯ            срок действия кода: 90s, 15m, 2h (по умолчанию 15m)
  --uses N               сколько устройств может войти (по умолчанию 1)
  --full                 показать постоянный ключ сети вместо короткого кода

Прочее:
  -v, --verbose          подробный лог
  -h, --help             эта справка

Пример: доступ к домашнему компьютеру через VPS
  на VPS:       quokka server --public vps.example.com
                quokka invite
  дома:         quokka join ABC-DEF-GHJ --peer vps.example.com --tcp 22 --name home
  на ноутбуке:  quokka join KMN-PQR-STV --peer vps.example.com --open home:22=2222
                ssh -p 2222 user@127.0.0.1
)";
}

CliOptions parse_cli(int argc, char** argv, const ProfileLoader& load_profile) {
    CliOptions opts;
    if (argc < 2) {
        opts.command = Command::Menu;
        return opts;
    }

    const std::string_view command = argv[1];
    int first_option = 2;
    if (command == "up") opts.command = Command::Up;
    else if (command == "server") opts.command = Command::Server;
    else if (command == "join") opts.command = Command::Join;
    else if (command == "invite") opts.command = Command::Invite;
    else if (command == "status") opts.command = Command::Status;
    else if (command == "list") opts.command = Command::List;
    else if (command == "connect") {
        opts.command = Command::Connect;
        if (argc < 3 || std::string_view(argv[2]).starts_with("-")) throw std::invalid_argument("connect: укажите имя сети");
        opts.profile = argv[2];
        first_option = 3;
    }
    else if (command == "-h" || command == "--help" || command == "help") return opts;
    else throw std::invalid_argument("Неизвестная команда '" + std::string(command) + "'");

    // --save определяет, какую сеть читать, поэтому узнаём его заранее
    for (int i = first_option; i + 1 < argc; ++i) {
        if (std::string_view(argv[i]) == "--save") {
            if (!is_valid_profile_name(argv[i + 1])) throw std::invalid_argument("--save: в имени только латиница, цифры, - и _");
            if (opts.command != Command::Connect) opts.profile = argv[i + 1];
        }
    }

    // Аргументы дополняют то, что записано в файле
    NodeConfig& c = opts.config;
    if (opts.command == Command::Connect) {
        auto stored = load_profile(opts.profile);
        if (!stored) throw std::invalid_argument("Сети '" + opts.profile + "' нет. Посмотреть список: quokka list");
        c = std::move(*stored);
    } else if (opts.command == Command::Up || opts.command == Command::Server) {
        if (auto stored = load_profile(opts.profile)) c = std::move(*stored);
    }
    if (opts.command == Command::Server) c.discovery = false;  // на VPS multicast не дойдёт ни до кого

    const bool is_up = opts.command == Command::Up || opts.command == Command::Server;
    const bool is_join = opts.command == Command::Join;
    const bool is_invite = opts.command == Command::Invite;

    for (int i = first_option; i < argc; ++i) {
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
        else if (is_invite && arg == "--ttl")        opts.invite_ttl = parse_duration(arg, value());
        else if (is_invite && arg == "--uses")       opts.invite_uses = static_cast<unsigned>(parse_number(arg, value(), 1000));
        else if (is_invite && arg == "--full")       opts.invite_full = true;
        else if (is_invite)                          throw std::invalid_argument("Неизвестный аргумент '" + std::string(arg) + "'");
        else if (arg == "--save")                    value();
        else if (arg == "--udp")                     add_service(c, ServiceProto::Udp, parse_port(arg, value()));
        else if (arg == "--tcp")                     add_service(c, ServiceProto::Tcp, parse_port(arg, value()));
        else if (arg == "--open")                    parse_open(c, value());
        else if (arg == "--peer")                    parse_peer(c, value());
        else if (arg == "--public")                  parse_public(c, value());
        else if (arg == "--no-discovery")            c.discovery = false;
        else if (arg == "--no-relay")                c.relay = false;
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
        else if (is_up && arg == "--new-invite")     opts.new_invite = true;
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
