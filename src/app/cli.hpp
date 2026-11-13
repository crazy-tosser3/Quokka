#pragma once

#include "core/config.hpp"

#include <chrono>
#include <functional>
#include <optional>
#include <string>

enum class Command { Help, Menu, Up, Server, Join, Connect, Invite, Status, List };

struct CliOptions {
    Command command{Command::Help};
    NodeConfig config;
    std::string profile;                // connect: имя сети; up/join: с --save
    std::optional<std::string> invite;  // join: код из аргументов
    bool new_invite = false;            // up: создать новую сеть
    bool no_save = false;               // join: не запоминать сеть
    bool verbose = false;

    // invite
    std::chrono::seconds invite_ttl{15 * 60};
    unsigned invite_uses = 1;
    bool invite_full = false;
};

// Настройки сети из файла: аргументы командной строки дополняют их. nullopt, если такой сети нет.
using ProfileLoader = std::function<std::optional<NodeConfig>(const std::string& name)>;

// Бросает std::invalid_argument с понятным сообщением при неверных аргументах.
// Код приглашения затирается в argv, чтобы его не было видно в списке процессов.
CliOptions parse_cli(int argc, char** argv, const ProfileLoader& load_profile);
std::string cli_usage();
