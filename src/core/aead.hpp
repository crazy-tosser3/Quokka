#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

class Aead {
public:
    using Key = std::array<unsigned char, 32>;
    using Packet = std::vector<unsigned char>;

    explicit Aead(const Key& key) : key_(key) {}

    Packet encrypt(const std::string& plaintext) const {
        if (plaintext.size() > static_cast<std::size_t>(INT_MAX)) {
            throw std::runtime_error("Message too large");
        }

        std::array<unsigned char, NONCE_SIZE> nonce{};

        if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }

        Ctx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }

        if (EVP_EncryptInit_ex(
                ctx.get(), EVP_chacha20_poly1305(),
                nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(
                ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                static_cast<int>(nonce.size()), nullptr) != 1 ||
            EVP_EncryptInit_ex(
                ctx.get(), nullptr, nullptr,
                key_.data(), nonce.data()) != 1) {
            throw std::runtime_error("AEAD initialization failed");
        }

        Packet packet(NONCE_SIZE + plaintext.size() + TAG_SIZE);
        std::copy(nonce.begin(), nonce.end(), packet.begin());

        int written = 0;
        int final_written = 0;

        if (EVP_EncryptUpdate(
                ctx.get(), packet.data() + NONCE_SIZE, &written,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())) != 1 ||
            EVP_EncryptFinal_ex(
                ctx.get(), packet.data() + NONCE_SIZE + written,
                &final_written) != 1) {
            throw std::runtime_error("AEAD encryption failed");
        }

        const auto ciphertext_size =
            static_cast<std::size_t>(written + final_written);

        packet.resize(NONCE_SIZE + ciphertext_size + TAG_SIZE);

        if (EVP_CIPHER_CTX_ctrl(
                ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                static_cast<int>(TAG_SIZE),
                packet.data() + NONCE_SIZE + ciphertext_size) != 1) {
            throw std::runtime_error("Failed to get AEAD tag");
        }

        return packet;
    }

    bool decrypt(const unsigned char* packet,
                 std::size_t packet_size,
                 std::string& plaintext) const {
        if (packet_size < NONCE_SIZE + TAG_SIZE ||
            packet_size - NONCE_SIZE - TAG_SIZE >
                static_cast<std::size_t>(INT_MAX)) {
            return false;
        }

        const auto* nonce = packet;
        const auto* ciphertext = packet + NONCE_SIZE;
        const std::size_t ciphertext_size =
            packet_size - NONCE_SIZE - TAG_SIZE;
        const auto* tag = ciphertext + ciphertext_size;

        Ctx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            return false;
        }

        if (EVP_DecryptInit_ex(
                ctx.get(), EVP_chacha20_poly1305(),
                nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(
                ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                static_cast<int>(NONCE_SIZE), nullptr) != 1 ||
            EVP_DecryptInit_ex(
                ctx.get(), nullptr, nullptr,
                key_.data(), nonce) != 1) {
            return false;
        }

        std::string result(ciphertext_size, '\0');
        int written = 0;
        int final_written = 0;

        if (EVP_DecryptUpdate(
                ctx.get(),
                reinterpret_cast<unsigned char*>(result.data()),
                &written, ciphertext,
                static_cast<int>(ciphertext_size)) != 1 ||
            EVP_CIPHER_CTX_ctrl(
                ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                static_cast<int>(TAG_SIZE),
                const_cast<unsigned char*>(tag)) != 1 ||
            EVP_DecryptFinal_ex(
                ctx.get(),
                reinterpret_cast<unsigned char*>(result.data()) + written,
                &final_written) != 1) {
            return false; // Tag invalid: reject packet.
        }

        result.resize(static_cast<std::size_t>(written + final_written));
        plaintext = std::move(result);
        return true;
    }

private:
    static constexpr std::size_t NONCE_SIZE = 12;
    static constexpr std::size_t TAG_SIZE = 16;
    using Ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    Key key_;
};
