#include "core/noise.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace noise {
namespace {

constexpr std::string_view PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256";
constexpr std::size_t KEY_SIZE = 32;
constexpr std::size_t TAG_SIZE = 16;

struct PkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct PkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct CipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };

[[noreturn]] void fail(const char* what) {
    throw std::runtime_error(std::string("Ошибка криптографии: ") + what);
}

Key dh(const Key& secret, const Key& peer_public) {
    std::unique_ptr<EVP_PKEY, PkeyDeleter> mine(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret.data(), secret.size()));
    std::unique_ptr<EVP_PKEY, PkeyDeleter> peer(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public.data(), peer_public.size()));
    if (!mine || !peer) fail("X25519");
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(EVP_PKEY_CTX_new(mine.get(), nullptr));
    Key out{};
    std::size_t size = out.size();
    // derive возвращает ошибку на точках малого порядка: такой ключ подсовывают намеренно
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1 ||
        EVP_PKEY_derive(ctx.get(), out.data(), &size) != 1 || size != out.size()) {
        throw std::invalid_argument("X25519: недопустимый ключ пира");
    }
    return out;
}

Key hmac(const uint8_t* key, std::size_t key_size, const uint8_t* data, std::size_t data_size) {
    Key out{};
    std::size_t size = out.size();
    if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key, key_size, data, data_size,
                   out.data(), out.size(), &size) || size != out.size()) {
        fail("HMAC");
    }
    return out;
}

// HKDF из спецификации Noise, раздел 4.3. Больше двух выходов нужно только для split().
template <std::size_t N>
std::array<Key, N> hkdf(const Key& chaining_key, const uint8_t* input, std::size_t input_size) {
    const Key temp = hmac(chaining_key.data(), chaining_key.size(), input, input_size);
    std::array<Key, N> out;
    Bytes block;
    for (std::size_t i = 0; i < N; ++i) {
        block.clear();
        if (i > 0) block.assign(out[i - 1].begin(), out[i - 1].end());
        block.push_back(static_cast<uint8_t>(i + 1));
        out[i] = hmac(temp.data(), temp.size(), block.data(), block.size());
    }
    return out;
}

std::array<uint8_t, 12> make_nonce(uint64_t counter) {
    std::array<uint8_t, 12> nonce{};
    for (int i = 0; i < 8; ++i) nonce[4 + i] = static_cast<uint8_t>(counter >> (8 * i));
    return nonce;
}

}

KeyPair keypair_from_secret(const Key& secret) {
    KeyPair pair;
    pair.secret = secret;
    std::unique_ptr<EVP_PKEY, PkeyDeleter> key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret.data(), secret.size()));
    std::size_t size = pair.public_key.size();
    if (!key || EVP_PKEY_get_raw_public_key(key.get(), pair.public_key.data(), &size) != 1) fail("X25519");
    return pair;
}

KeyPair generate_keypair() {
    Key secret;
    if (RAND_bytes(secret.data(), static_cast<int>(secret.size())) != 1) fail("RAND_bytes");
    return keypair_from_secret(secret);
}

Bytes seal(const Key& key, uint64_t counter, const uint8_t* aad, std::size_t aad_size,
           const uint8_t* plain, std::size_t plain_size) {
    const auto nonce = make_nonce(counter);
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx(EVP_CIPHER_CTX_new());
    Bytes out(plain_size + TAG_SIZE);
    int written = 0;
    int final_written = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1 ||
        (aad_size > 0 && EVP_EncryptUpdate(ctx.get(), nullptr, &written, aad, static_cast<int>(aad_size)) != 1) ||
        EVP_EncryptUpdate(ctx.get(), out.data(), &written, plain, static_cast<int>(plain_size)) != 1 ||
        EVP_EncryptFinal_ex(ctx.get(), out.data() + written, &final_written) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, out.data() + plain_size) != 1) {
        fail("шифрование");
    }
    return out;
}

std::optional<Bytes> open(const Key& key, uint64_t counter, const uint8_t* aad, std::size_t aad_size,
                          const uint8_t* cipher, std::size_t cipher_size) {
    if (cipher_size < TAG_SIZE) return std::nullopt;
    const std::size_t plain_size = cipher_size - TAG_SIZE;
    const auto nonce = make_nonce(counter);
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx(EVP_CIPHER_CTX_new());
    // Дополнительный байт: пустому сообщению тоже нужен действительный указатель
    Bytes out(plain_size + 1);
    int written = 0;
    int final_written = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1 ||
        (aad_size > 0 && EVP_DecryptUpdate(ctx.get(), nullptr, &written, aad, static_cast<int>(aad_size)) != 1) ||
        EVP_DecryptUpdate(ctx.get(), out.data(), &written, cipher, static_cast<int>(plain_size)) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, TAG_SIZE,
                            const_cast<uint8_t*>(cipher + plain_size)) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), out.data() + written, &final_written) != 1) {
        return std::nullopt;
    }
    out.resize(plain_size);
    return out;
}

Handshake::Handshake(bool initiator, const KeyPair& local_static, const Bytes& prologue)
    : Handshake(initiator, local_static, prologue, generate_keypair()) {}

Handshake::Handshake(bool initiator, const KeyPair& local_static, const Bytes& prologue, const KeyPair& fixed_ephemeral)
    : initiator_(initiator), static_(local_static), ephemeral_(fixed_ephemeral) {
    SHA256(reinterpret_cast<const unsigned char*>(PROTOCOL_NAME.data()), PROTOCOL_NAME.size(), hash_.data());
    std::copy(hash_.begin(), hash_.end(), chaining_key_.begin());
    mix_hash(prologue.data(), prologue.size());
}

void Handshake::mix_hash(const uint8_t* data, std::size_t size) {
    Bytes input(hash_.begin(), hash_.end());
    input.insert(input.end(), data, data + size);
    SHA256(input.data(), input.size(), hash_.data());
}

void Handshake::mix_key(const Key& input) {
    const auto out = hkdf<2>(chaining_key_, input.data(), input.size());
    chaining_key_ = out[0];
    cipher_key_ = out[1];
    has_key_ = true;
    nonce_ = 0;
}

Bytes Handshake::encrypt_and_hash(const Bytes& plain) {
    if (!has_key_) {
        mix_hash(plain.data(), plain.size());
        return plain;
    }
    Bytes cipher = seal(cipher_key_, nonce_++, hash_.data(), hash_.size(), plain.data(), plain.size());
    mix_hash(cipher.data(), cipher.size());
    return cipher;
}

std::optional<Bytes> Handshake::decrypt_and_hash(const uint8_t* cipher, std::size_t size) {
    if (!has_key_) {
        mix_hash(cipher, size);
        return Bytes(cipher, cipher + size);
    }
    auto plain = open(cipher_key_, nonce_, hash_.data(), hash_.size(), cipher, size);
    if (!plain) return std::nullopt;
    ++nonce_;
    mix_hash(cipher, size);
    return plain;
}

// -> e
// <- e, ee, s, es
// -> s, se
Bytes Handshake::write_message(const Bytes& payload) {
    const bool my_turn = (step_ == 1) != initiator_;
    if (!my_turn || step_ > 2) fail("сообщение рукопожатия не по очереди");

    Bytes out;
    const auto append = [&out](const auto& data) { out.insert(out.end(), data.begin(), data.end()); };

    if (step_ == 0) {
        append(ephemeral_.public_key);
        mix_hash(ephemeral_.public_key.data(), ephemeral_.public_key.size());
    } else if (step_ == 1) {
        append(ephemeral_.public_key);
        mix_hash(ephemeral_.public_key.data(), ephemeral_.public_key.size());
        mix_key(dh(ephemeral_.secret, remote_ephemeral_));
        append(encrypt_and_hash(Bytes(static_.public_key.begin(), static_.public_key.end())));
        mix_key(dh(static_.secret, remote_ephemeral_));
    } else {
        append(encrypt_and_hash(Bytes(static_.public_key.begin(), static_.public_key.end())));
        mix_key(dh(static_.secret, remote_ephemeral_));
    }
    append(encrypt_and_hash(payload));
    ++step_;
    return out;
}

std::optional<Bytes> Handshake::read_message(const uint8_t* data, std::size_t size) {
    const bool my_turn = (step_ == 1) == initiator_;
    if (!my_turn || step_ > 2) return std::nullopt;

    const uint8_t* cursor = data;
    std::size_t left = size;
    const auto read_ephemeral = [&] {
        if (left < KEY_SIZE) return false;
        std::copy_n(cursor, KEY_SIZE, remote_ephemeral_.begin());
        mix_hash(cursor, KEY_SIZE);
        cursor += KEY_SIZE;
        left -= KEY_SIZE;
        return true;
    };
    const auto read_static = [&] {
        const std::size_t cipher_size = KEY_SIZE + TAG_SIZE;
        if (left < cipher_size) return false;
        const auto plain = decrypt_and_hash(cursor, cipher_size);
        if (!plain) return false;
        std::copy_n(plain->begin(), KEY_SIZE, remote_static_.begin());
        cursor += cipher_size;
        left -= cipher_size;
        return true;
    };

    try {
        if (step_ == 0) {
            if (!read_ephemeral()) return std::nullopt;
        } else if (step_ == 1) {
            if (!read_ephemeral()) return std::nullopt;
            mix_key(dh(ephemeral_.secret, remote_ephemeral_));
            if (!read_static()) return std::nullopt;
            mix_key(dh(ephemeral_.secret, remote_static_));
        } else {
            if (!read_static()) return std::nullopt;
            mix_key(dh(ephemeral_.secret, remote_static_));
        }
    } catch (const std::invalid_argument&) {
        return std::nullopt;  // ключ малого порядка
    }

    auto payload = decrypt_and_hash(cursor, left);
    if (!payload) return std::nullopt;
    ++step_;
    return payload;
}

TransportKeys Handshake::split() const {
    if (!finished()) fail("рукопожатие не завершено");
    const auto keys = hkdf<4>(chaining_key_, nullptr, 0);
    return TransportKeys{keys[0], keys[1], keys[2], keys[3]};
}

bool ReplayWindow::accept(uint64_t counter) {
    const auto bit = [this](uint64_t value) -> std::pair<uint64_t&, uint64_t> {
        const uint64_t slot = value % SIZE;
        return {bits_[slot / 64], uint64_t{1} << (slot % 64)};
    };

    if (!seen_any_ || counter > highest_) {
        const uint64_t distance = seen_any_ ? counter - highest_ : SIZE;
        if (distance >= SIZE) {
            bits_.fill(0);
        } else {
            for (uint64_t value = highest_ + 1; value <= counter; ++value) {
                auto [word, mask] = bit(value);
                word &= ~mask;
            }
        }
        highest_ = counter;
        seen_any_ = true;
        auto [word, mask] = bit(counter);
        word |= mask;
        return true;
    }
    if (highest_ - counter >= SIZE) return false;
    auto [word, mask] = bit(counter);
    if (word & mask) return false;
    word |= mask;
    return true;
}

}
