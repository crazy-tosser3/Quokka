#include "app/profiles.hpp"

#include "core/identity.hpp"
#include "core/routing.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace {

constexpr std::string_view SECTION_PREFIX = "network.";

constexpr std::string_view FILE_HEADER =
    "# Настройки Quokka. Выбрать сеть: quokka или quokka connect ИМЯ\n"
    "# Этот файл содержит ключи сетей: не передавайте его и не меняйте права (должно быть 600).\n";

// Значение из файла: строка, число, логическое или массив
struct Value {
    enum class Kind { String, Number, Bool, Array } kind{Kind::String};
    std::string text;
    long long number{0};
    bool flag{false};
    std::vector<Value> items;
};

std::string trim(std::string_view text) {
    const auto begin = text.find_first_not_of(" \t\r");
    if (begin == std::string_view::npos) return {};
    const auto end = text.find_last_not_of(" \t\r");
    return std::string(text.substr(begin, end - begin + 1));
}

class ValueParser {
public:
    explicit ValueParser(std::string_view text) : text_(text) {}

    Value parse() {
        Value value = parse_value();
        skip();
        if (pos_ < text_.size() && text_[pos_] != '#') throw std::invalid_argument("лишний текст после значения");
        return value;
    }

private:
    void skip() {
        while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\t' || text_[pos_] == '\r')) ++pos_;
    }

    Value parse_value() {
        skip();
        if (pos_ >= text_.size()) throw std::invalid_argument("нет значения");
        const char c = text_[pos_];
        if (c == '"') return parse_string();
        if (c == '[') return parse_array();
        return parse_scalar();
    }

    Value parse_string() {
        Value value;
        ++pos_;
        while (pos_ < text_.size() && text_[pos_] != '"') {
            if (text_[pos_] == '\\') throw std::invalid_argument("escape-последовательности в строках не поддерживаются");
            value.text += text_[pos_++];
        }
        if (pos_ >= text_.size()) throw std::invalid_argument("строка не закрыта");
        ++pos_;
        return value;
    }

    Value parse_array() {
        Value value;
        value.kind = Value::Kind::Array;
        ++pos_;
        for (;;) {
            skip();
            if (pos_ >= text_.size()) throw std::invalid_argument("массив не закрыт");
            if (text_[pos_] == ']') {
                ++pos_;
                return value;
            }
            value.items.push_back(parse_value());
            skip();
            if (pos_ >= text_.size()) throw std::invalid_argument("массив не закрыт");
            if (text_[pos_] == ',') ++pos_;
            else if (text_[pos_] != ']') throw std::invalid_argument("в массиве нужна запятая");
        }
    }

    Value parse_scalar() {
        const auto begin = pos_;
        while (pos_ < text_.size() && text_[pos_] != ',' && text_[pos_] != ']' && text_[pos_] != '#' &&
               text_[pos_] != ' ' && text_[pos_] != '\t' && text_[pos_] != '\r') {
            ++pos_;
        }
        const std::string_view token = text_.substr(begin, pos_ - begin);
        Value value;
        if (token == "true" || token == "false") {
            value.kind = Value::Kind::Bool;
            value.flag = token == "true";
            return value;
        }
        value.kind = Value::Kind::Number;
        const auto [ptr, err] = std::from_chars(token.data(), token.data() + token.size(), value.number);
        if (err != std::errc{} || ptr != token.data() + token.size()) {
            throw std::invalid_argument("неизвестное значение '" + std::string(token) + "', строки пишутся в кавычках");
        }
        return value;
    }

    std::string_view text_;
    std::size_t pos_{0};
};

std::string as_string(const Value& value, std::string_view key) {
    if (value.kind != Value::Kind::String) throw std::invalid_argument(std::string(key) + ": нужна строка");
    return value.text;
}

bool as_bool(const Value& value, std::string_view key) {
    if (value.kind != Value::Kind::Bool) throw std::invalid_argument(std::string(key) + ": нужно true или false");
    return value.flag;
}

std::string as_port_text(const Value& value, std::string_view key) {
    if (value.kind == Value::Kind::Number) return std::to_string(value.number);
    return as_string(value, key);
}

const std::vector<Value>& as_array(const Value& value, std::string_view key) {
    if (value.kind != Value::Kind::Array) throw std::invalid_argument(std::string(key) + ": нужен массив, например [22, 8000]");
    return value.items;
}

void apply_key(Profile& profile, const std::string& key, const Value& value) {
    NodeConfig& c = profile.config;
    if (key == "code") {
        profile.code = as_string(value, key);
        if (!identity::decode_invite(profile.code)) throw std::invalid_argument("code: ключ сети повреждён");
    } else if (key == "name") {
        c.name = as_string(value, key);
        if (!routing::is_valid_name(c.name)) throw std::invalid_argument("name: слишком длинное или с управляющими символами");
    } else if (key == "tcp" || key == "udp") {
        const auto proto = key == "tcp" ? ServiceProto::Tcp : ServiceProto::Udp;
        for (const Value& item : as_array(value, key)) add_service(c, proto, parse_port(key, as_port_text(item, key)));
    } else if (key == "open") {
        for (const Value& item : as_array(value, key)) parse_open(c, as_port_text(item, key));
    } else if (key == "peers") {
        for (const Value& item : as_array(value, key)) parse_peer(c, as_string(item, key));
    } else if (key == "public") {
        c.public_address = as_string(value, key);
    } else if (key == "relay") {
        c.relay = as_bool(value, key);
    } else if (key == "discovery") {
        c.discovery = as_bool(value, key);
    } else if (key == "discovery_port") {
        c.discovery_port = parse_port(key, as_port_text(value, key));
    } else if (key == "multicast_ip") {
        c.multicast_ip = as_string(value, key);
    } else if (key == "port") {
        c.quic_port = parse_port(key, as_port_text(value, key));
        c.quic_port_explicit = true;
    } else if (key == "listeners") {
        if (value.kind != Value::Kind::Number || value.number <= 0) throw std::invalid_argument("listeners: нужно число больше нуля");
        c.max_listeners = static_cast<std::size_t>(value.number);
    } else {
        throw std::invalid_argument("неизвестная настройка '" + key + "'");
    }
}

std::string open_rule_text(const OpenRule& rule) {
    if (rule.port == 0) return "all";
    std::string text;
    if (!rule.node.empty()) text = rule.node + ":";
    text += std::to_string(rule.port);
    if (rule.local_port != 0) text += "=" + std::to_string(rule.local_port);
    return text;
}

std::string profile_text(const std::string& name, const Profile& profile) {
    const NodeConfig& c = profile.config;
    const NodeConfig defaults;
    std::ostringstream out;
    out << "[network." << name << "]\n";
    out << "code = \"" << profile.code << "\"\n";
    if (!c.name.empty()) out << "name = \"" << c.name << "\"\n";

    if (!c.peers.empty()) {
        out << "peers = [";
        for (std::size_t i = 0; i < c.peers.size(); ++i) {
            out << (i ? ", " : "") << "\"" << c.peers[i].host << ":" << c.peers[i].port << "\"";
        }
        out << "]\n";
    }
    const auto write_ports = [&](std::string_view key, ServiceProto proto) {
        std::vector<uint16_t> ports;
        for (const Service& service : c.services) {
            if (service.proto == proto) ports.push_back(service.port);
        }
        if (ports.empty()) return;
        out << key << " = [";
        for (std::size_t i = 0; i < ports.size(); ++i) out << (i ? ", " : "") << ports[i];
        out << "]\n";
    };
    write_ports("tcp", ServiceProto::Tcp);
    write_ports("udp", ServiceProto::Udp);
    if (!c.open_rules.empty()) {
        out << "open = [";
        for (std::size_t i = 0; i < c.open_rules.size(); ++i) {
            out << (i ? ", " : "") << "\"" << open_rule_text(c.open_rules[i]) << "\"";
        }
        out << "]\n";
    }
    if (!c.public_address.empty()) out << "public = \"" << c.public_address << "\"\n";
    if (c.relay != defaults.relay) out << "relay = " << (c.relay ? "true" : "false") << "\n";
    if (c.discovery != defaults.discovery) out << "discovery = " << (c.discovery ? "true" : "false") << "\n";
    if (c.discovery_port != defaults.discovery_port) out << "discovery_port = " << c.discovery_port << "\n";
    if (c.multicast_ip != defaults.multicast_ip) out << "multicast_ip = \"" << c.multicast_ip << "\"\n";
    if (c.quic_port_explicit) out << "port = " << c.quic_port << "\n";
    if (c.max_listeners) out << "listeners = " << *c.max_listeners << "\n";
    return out.str();
}

}

uint16_t parse_port(std::string_view name, std::string_view value) {
    unsigned long long number = 0;
    auto [ptr, err] = std::from_chars(value.data(), value.data() + value.size(), number);
    if (err != std::errc{} || ptr != value.data() + value.size() || number == 0 || number > 65535) {
        throw std::invalid_argument(std::string(name) + ": неверное значение '" + std::string(value) + "'");
    }
    return static_cast<uint16_t>(number);
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
        peer.port = parse_port("peer", value.substr(colon + 1));
    }
    if (peer.host.empty()) throw std::invalid_argument("peer: не указан адрес");
    for (const PeerAddress& existing : config.peers) {
        if (existing.host == peer.host && existing.port == peer.port) return;
    }
    config.peers.push_back(std::move(peer));
}

// [УЗЕЛ:]ПОРТ[=ЛОКАЛЬНЫЙ] или all
void parse_open(NodeConfig& config, std::string_view value) {
    OpenRule rule;
    if (value != "all") {
        if (const auto eq = value.find('='); eq != std::string_view::npos) {
            rule.local_port = parse_port("open", value.substr(eq + 1));
            value = value.substr(0, eq);
        }
        if (const auto colon = value.rfind(':'); colon != std::string_view::npos) {
            rule.node = value.substr(0, colon);
            value = value.substr(colon + 1);
            if (rule.node.empty()) throw std::invalid_argument("open: не указан узел");
        }
        rule.port = parse_port("open", value);
    }
    for (const OpenRule& existing : config.open_rules) {
        if (existing.node == rule.node && existing.port == rule.port && existing.local_port == rule.local_port) return;
    }
    config.open_rules.push_back(std::move(rule));
}

bool is_valid_profile_name(std::string_view name) {
    return !name.empty() && name.size() <= 32 && std::all_of(name.begin(), name.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    });
}

std::filesystem::path config_path() {
    return identity::state_dir() / "config.toml";
}

ProfileFile load_profiles() {
    ProfileFile file;
    const auto path = config_path();
    const auto content = identity::read_private_file(path);
    if (!content) return file;

    Profile* current = nullptr;
    std::istringstream lines(*content);
    std::string line;
    int number = 0;
    while (std::getline(lines, line)) {
        ++number;
        const std::string text = trim(line);
        if (text.empty() || text[0] == '#') continue;
        try {
            if (text.front() == '[') {
                const auto close = text.find(']');
                if (close == std::string::npos) throw std::invalid_argument("секция не закрыта");
                const std::string section = text.substr(1, close - 1);
                if (!section.starts_with(SECTION_PREFIX)) throw std::invalid_argument("секция должна называться [network.ИМЯ]");
                const std::string name = section.substr(SECTION_PREFIX.size());
                if (!is_valid_profile_name(name)) throw std::invalid_argument("в имени сети только латиница, цифры, - и _");
                current = &file.profiles[name];
                continue;
            }
            const auto eq = text.find('=');
            if (eq == std::string::npos) throw std::invalid_argument("ожидается ключ = значение");
            const std::string key = trim(std::string_view(text).substr(0, eq));
            const Value value = ValueParser(std::string_view(text).substr(eq + 1)).parse();
            if (!current) {
                if (key != "default") throw std::invalid_argument("неизвестная настройка '" + key + "'");
                file.default_name = as_string(value, key);
                continue;
            }
            apply_key(*current, key, value);
        } catch (const std::invalid_argument& e) {
            throw std::runtime_error(path.string() + ", строка " + std::to_string(number) + ": " + e.what());
        }
    }

    for (const auto& [name, profile] : file.profiles) {
        if (profile.code.empty()) throw std::runtime_error(path.string() + ": в сети '" + name + "' нет code");
    }
    if (!file.default_name.empty() && !file.profiles.contains(file.default_name)) {
        throw std::runtime_error(path.string() + ": default указывает на неизвестную сеть '" + file.default_name + "'");
    }
    return file;
}

void save_profile(const std::string& name, const Profile& profile, bool make_default) {
    const auto path = config_path();
    const auto content = identity::read_private_file(path);

    const std::string header = "[network." + name + "]";
    std::vector<std::string> kept;
    bool skipping = false;
    bool default_written = false;
    if (content) {
        std::istringstream lines(*content);
        std::string line;
        while (std::getline(lines, line)) {
            const std::string text = trim(line);
            if (!text.empty() && text.front() == '[') skipping = text == header;
            if (skipping) continue;
            if (make_default && text.starts_with("default") && text.find('=') != std::string::npos) {
                kept.push_back("default = \"" + name + "\"");
                default_written = true;
                continue;
            }
            kept.push_back(line);
        }
    } else {
        std::istringstream lines{std::string(FILE_HEADER)};
        std::string line;
        while (std::getline(lines, line)) kept.push_back(line);
    }
    while (!kept.empty() && trim(kept.back()).empty()) kept.pop_back();

    if (make_default && !default_written) {
        // default должен идти до первой секции
        const auto first = std::find_if(kept.begin(), kept.end(), [](const std::string& l) {
            const std::string text = trim(l);
            return !text.empty() && text.front() == '[';
        });
        kept.insert(first, "default = \"" + name + "\"");
    }

    std::string out;
    for (const std::string& line : kept) out += line + "\n";
    if (!out.empty()) out += "\n";
    out += profile_text(name, profile);
    identity::write_private_file(path, out);
}
