#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

// Сквозное шифрование между узлами сети: рукопожатие Noise_XX_25519_ChaChaPoly_SHA256
// (noiseprotocol.org). Промежуточные узлы не могут ни прочитать, ни незаметно изменить трафик.
namespace noise {

using Bytes = std::vector<uint8_t>;
using Key = std::array<uint8_t, 32>;

struct KeyPair {
    Key secret{};
    Key public_key{};
};

KeyPair generate_keypair();
KeyPair keypair_from_secret(const Key& secret);

// Шифрование с явным счётчиком вместо nonce. Один счётчик с одним ключом использовать нельзя.
Bytes seal(const Key& key, uint64_t counter, const uint8_t* aad, std::size_t aad_size,
           const uint8_t* plain, std::size_t plain_size);
std::optional<Bytes> open(const Key& key, uint64_t counter, const uint8_t* aad, std::size_t aad_size,
                          const uint8_t* cipher, std::size_t cipher_size);

// Ключи после рукопожатия, в направлении initiator -> responder и обратно
struct TransportKeys {
    Key stream_i2r{};
    Key stream_r2i{};
    Key datagram_i2r{};
    Key datagram_r2i{};
};

class Handshake {
public:
    Handshake(bool initiator, const KeyPair& local_static, const Bytes& prologue);
    Handshake(bool initiator, const KeyPair& local_static, const Bytes& prologue, const KeyPair& fixed_ephemeral);

    // Сообщения идут по очереди: initiator пишет 1 и 3, responder пишет 2.
    // payload шифруется, начиная со второго сообщения.
    Bytes write_message(const Bytes& payload);
    // nullopt, если сообщение подделано или повреждено: рукопожатие после этого не продолжить
    std::optional<Bytes> read_message(const uint8_t* data, std::size_t size);

    bool finished() const { return step_ == 3; }
    const Key& remote_static() const { return remote_static_; }
    TransportKeys split() const;

private:
    void mix_hash(const uint8_t* data, std::size_t size);
    void mix_key(const Key& input);
    Bytes encrypt_and_hash(const Bytes& plain);
    std::optional<Bytes> decrypt_and_hash(const uint8_t* cipher, std::size_t size);

    bool initiator_;
    int step_{0};
    KeyPair static_;
    KeyPair ephemeral_;
    Key remote_static_{};
    Key remote_ephemeral_{};
    Key chaining_key_{};
    std::array<uint8_t, 32> hash_{};
    Key cipher_key_{};
    bool has_key_{false};
    uint64_t nonce_{0};
};

// Защита от повтора датаграмм: пропускает каждый счётчик один раз, старые отбрасывает
class ReplayWindow {
public:
    bool accept(uint64_t counter);

private:
    static constexpr uint64_t SIZE = 2048;
    std::array<uint64_t, SIZE / 64> bits_{};
    uint64_t highest_{0};
    bool seen_any_{false};
};

}
