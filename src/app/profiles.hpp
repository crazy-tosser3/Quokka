#pragma once

#include "core/config.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct Profile {
    std::string code;
    NodeConfig config;
};

struct ProfileFile {
    std::string default_name;
    std::map<std::string, Profile> profiles;
};

std::filesystem::path config_path();

// Бросает std::runtime_error с номером строки, если файл написан неверно или доступен другим
ProfileFile load_profiles();

// Заменяет секцию этой сети, остальной текст файла с комментариями не трогает
void save_profile(const std::string& name, const Profile& profile, bool make_default);

bool is_valid_profile_name(std::string_view name);

// Разбор значений, общий для файла настроек и командной строки. Бросают std::invalid_argument.
uint16_t parse_port(std::string_view name, std::string_view value);
void add_service(NodeConfig& config, ServiceProto proto, uint16_t port);
void parse_peer(NodeConfig& config, std::string_view value);
void parse_open(NodeConfig& config, std::string_view value);
