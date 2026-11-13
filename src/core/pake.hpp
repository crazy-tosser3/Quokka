#pragma once

#include "core/noise.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Короткий код приглашения вида ABC-DEF-GHJ и SPAKE2 на P-256 (RFC 9382).
//
// В коде всего 40 бит, поэтому выводить из него ключи напрямую нельзя: их перебрали бы офлайн.
// SPAKE2 не даёт такой возможности: за одно подключение можно проверить только одну догадку,
// а подключения считает сторона, выдавшая код. Подробности — docs/SECURITY.md.
namespace pake {

using Bytes = std::vector<uint8_t>;

// 8 случайных символов base32 (40 бит) и контрольный: опечатка не тратит попытку
std::string generate_code();
// Каноничная запись кода; nullopt, если это не код или в нём опечатка
std::optional<std::string> normalize_code(std::string_view text);

struct SessionKeys {
    noise::Key encryption{};
    noise::Key confirm_client{};
    noise::Key confirm_server{};
};

inline constexpr std::size_t POINT_SIZE = 65;  // несжатая точка P-256
inline constexpr std::size_t CONFIRM_SIZE = 32;

class Spake2 {
public:
    Spake2(bool client, const std::string& code);
    ~Spake2();
    Spake2(const Spake2&) = delete;
    Spake2& operator=(const Spake2&) = delete;

    // Своё сообщение, отправляется другой стороне
    const Bytes& message() const { return message_; }
    // nullopt, если сообщение пира не является допустимой точкой
    std::optional<SessionKeys> finish(const uint8_t* peer, std::size_t size) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    bool client_;
    Bytes message_;
};

// Подтверждение ключа: без него нельзя понять, совпали ли коды
std::array<uint8_t, CONFIRM_SIZE> confirmation(const noise::Key& key);
bool confirmation_matches(const noise::Key& key, const uint8_t* value, std::size_t size);

}
