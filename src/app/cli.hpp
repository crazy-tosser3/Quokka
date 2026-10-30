#pragma once

#include "core/config.hpp"

#include <optional>
#include <string>

enum class Command { Help, Up, Join };

struct CliOptions {
    Command command{Command::Help};
    NodeConfig config;
    std::optional<std::string> invite;  // код из аргументов join
    bool new_invite = false;            // up: создать новую сеть с новым кодом
    bool no_save = false;               // join: не запоминать код
    bool verbose = false;
};

// Бросает std::invalid_argument с понятным сообщением при неверных аргументах.
// Код приглашения затирается в argv, чтобы его не было видно в списке процессов.
CliOptions parse_cli(int argc, char** argv);
std::string cli_usage();
