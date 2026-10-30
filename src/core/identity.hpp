#pragma once

#include "core/aead.hpp"
#include "core/noise.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Ключи и код приглашения. Подробности и модель угроз — docs/SECURITY.md.
namespace identity {

using Bytes = std::vector<uint8_t>;
using Seed = std::array<uint8_t, 32>;      // закрытый ключ Ed25519
using PublicKey = std::array<uint8_t, 32>; // открытый ключ Ed25519
using Signature = std::array<uint8_t, 64>;
using Secret = std::array<uint8_t, 16>;    // секрет сети
using Pin = std::array<uint8_t, 16>;       // усечённый SHA-256 от SubjectPublicKeyInfo
using NodeId = std::array<uint8_t, 16>;    // усечённый SHA-256 от открытого ключа узла

// Код приглашения: всё, что нужно для входа в сеть
struct Invite {
    Secret secret{};
};

std::string encode_invite(const Invite& invite);
// nullopt, если код повреждён (проверяется контрольная сумма)
std::optional<Invite> decode_invite(std::string_view text);
Invite make_invite();

// Ключи соседних соединений: выводятся из секрета и одинаковы у всех участников.
// Доказывают только членство в сети, но не то, какой это узел.
struct NetworkKeys {
    Bytes pkcs12;              // сертификат и ключ для MsQuic
    Pin link_pin{};            // ключ, который обязан предъявить сосед
    Aead::Key discovery_key{}; // шифрование маяков
};

NetworkKeys network_keys(const Invite& invite);

// Личность узла: своя у каждого, не покидает машину.
// Идентификатор — хеш ключа, поэтому присвоить чужой идентификатор нельзя.
struct NodeIdentity {
    Seed signing_seed{};
    PublicKey signing_public{};
    noise::KeyPair static_key;  // сквозное шифрование
    NodeId id{};
};

NodeIdentity identity_from_keys(const Seed& signing_seed, const noise::Key& static_secret);
NodeIdentity generate_identity();

Signature sign(const NodeIdentity& node, const uint8_t* data, std::size_t size);
bool verify(const PublicKey& key, const uint8_t* data, std::size_t size, const Signature& signature);
NodeId node_id_of(const PublicKey& key);
std::string short_id(const NodeId& id);  // первые 8 символов hex
std::string to_hex(const uint8_t* data, std::size_t size);

// Создаёт самоподписанный сертификат на ключе seed и упаковывает его в PKCS#12
Bytes make_pkcs12(const Seed& seed);
Pin pin_of_seed(const Seed& seed);
// Отпечаток ключа из сертификата в DER; nullopt, если это не Ed25519 или мусор
std::optional<Pin> pin_of_certificate(const uint8_t* der, std::size_t length);

// $QUOKKA_HOME, иначе $XDG_CONFIG_HOME/quokka, иначе ~/.config/quokka
std::filesystem::path state_dir();

// Бросают std::runtime_error, если файл доступен другим пользователям
NodeIdentity load_or_create_identity(const std::filesystem::path& dir);
std::optional<Invite> load_saved_invite(const std::filesystem::path& dir);
void save_invite(const std::filesystem::path& dir, const Invite& invite);

}
