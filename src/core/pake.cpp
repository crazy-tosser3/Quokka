#include "core/pake.hpp"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace pake {
namespace {

constexpr std::string_view ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";  // Crockford
constexpr std::size_t CODE_CHARS = 9;

struct BnDeleter { void operator()(BIGNUM* p) const { BN_clear_free(p); } };
struct PointDeleter { void operator()(EC_POINT* p) const { EC_POINT_clear_free(p); } };
struct GroupDeleter { void operator()(EC_GROUP* p) const { EC_GROUP_free(p); } };
struct CtxDeleter { void operator()(BN_CTX* p) const { BN_CTX_free(p); } };
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using PointPtr = std::unique_ptr<EC_POINT, PointDeleter>;
using GroupPtr = std::unique_ptr<EC_GROUP, GroupDeleter>;
using CtxPtr = std::unique_ptr<BN_CTX, CtxDeleter>;

[[noreturn]] void fail(const char* what) {
    throw std::runtime_error(std::string("Ошибка криптографии: ") + what);
}

char check_char(std::string_view data) {
    constexpr std::string_view domain = "quokka-short-code-v1";
    Bytes input(domain.begin(), domain.end());
    input.insert(input.end(), data.begin(), data.end());
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(input.data(), input.size(), digest);
    return ALPHABET[digest[0] % ALPHABET.size()];
}

noise::Key hmac(const uint8_t* key, std::size_t key_size, const uint8_t* data, std::size_t size) {
    noise::Key out{};
    std::size_t length = out.size();
    if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key, key_size, data, size,
                   out.data(), out.size(), &length) || length != out.size()) {
        fail("HMAC");
    }
    return out;
}

noise::Key label_key(const noise::Key& key, std::string_view label) {
    return hmac(key.data(), key.size(), reinterpret_cast<const uint8_t*>(label.data()), label.size());
}

const EC_GROUP* group() {
    static const GroupPtr instance(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    if (!instance) fail("P-256");
    return instance.get();
}

// Точка, дискретный логарифм которой никому не известен: хеш от публичной метки.
// Это тот же подход, каким получены константы M и N в RFC 9382, но метка своя.
PointPtr nothing_up_my_sleeve(std::string_view label) {
    CtxPtr ctx(BN_CTX_new());
    PointPtr point(EC_POINT_new(group()));
    for (uint32_t counter = 0; counter < 1024; ++counter) {
        Bytes input(label.begin(), label.end());
        for (int shift = 24; shift >= 0; shift -= 8) input.push_back(uint8_t(counter >> shift));
        std::array<uint8_t, 33> encoded{};
        encoded[0] = 0x02;
        SHA256(input.data(), input.size(), encoded.data() + 1);
        if (EC_POINT_oct2point(group(), point.get(), encoded.data(), encoded.size(), ctx.get()) == 1) return point;
    }
    fail("не удалось построить точку");
}

const EC_POINT* point_m() {
    static const PointPtr instance = nothing_up_my_sleeve("quokka-spake2-v1 M");
    return instance.get();
}

const EC_POINT* point_n() {
    static const PointPtr instance = nothing_up_my_sleeve("quokka-spake2-v1 N");
    return instance.get();
}

Bytes encode_point(const EC_POINT* point, BN_CTX* ctx) {
    Bytes out(POINT_SIZE);
    if (EC_POINT_point2oct(group(), point, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), ctx) != POINT_SIZE) {
        fail("кодирование точки");
    }
    return out;
}

void append_framed(Bytes& out, const uint8_t* data, std::size_t size) {
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(uint8_t(uint64_t(size) >> shift));
    out.insert(out.end(), data, data + size);
}

}

std::string generate_code() {
    std::array<uint8_t, CODE_CHARS - 1> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) fail("RAND_bytes");
    std::string data;
    for (const uint8_t byte : random) data += ALPHABET[byte & 0x1F];
    const std::string all = data + check_char(data);
    return all.substr(0, 3) + "-" + all.substr(3, 3) + "-" + all.substr(6, 3);
}

std::optional<std::string> normalize_code(std::string_view text) {
    std::string clean;
    for (char c : text) {
        if (c == ' ' || c == '-' || c == '\t' || c == '\n' || c == '\r') continue;
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        if (c == 'I' || c == 'L') c = '1';
        if (c == 'O') c = '0';
        if (ALPHABET.find(c) == std::string_view::npos) return std::nullopt;
        clean += c;
    }
    if (clean.size() != CODE_CHARS) return std::nullopt;
    if (check_char(std::string_view(clean).substr(0, CODE_CHARS - 1)) != clean.back()) return std::nullopt;
    return clean.substr(0, 3) + "-" + clean.substr(3, 3) + "-" + clean.substr(6, 3);
}

struct Spake2::Impl {
    BnPtr scalar;
    BnPtr password;
};

Spake2::Spake2(bool client, const std::string& code) : impl_(std::make_unique<Impl>()), client_(client) {
    CtxPtr ctx(BN_CTX_new());
    BnPtr order(BN_new());
    if (!ctx || !order || EC_GROUP_get_order(group(), order.get(), ctx.get()) != 1) fail("порядок группы");

    constexpr std::string_view domain = "quokka-spake2-v1 password";
    Bytes input(domain.begin(), domain.end());
    input.insert(input.end(), code.begin(), code.end());
    // Хеш шире порядка группы: смещение при взятии остатка пренебрежимо мало
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(input.data(), input.size(), digest);
    impl_->password.reset(BN_bin2bn(digest, sizeof(digest), nullptr));
    impl_->scalar.reset(BN_new());
    if (!impl_->password || !impl_->scalar ||
        BN_mod(impl_->password.get(), impl_->password.get(), order.get(), ctx.get()) != 1 ||
        BN_priv_rand_range(impl_->scalar.get(), order.get()) != 1 || BN_is_zero(impl_->scalar.get())) {
        fail("случайное число");
    }

    // X = x*G + w*M у клиента, Y = y*G + w*N у сервера
    PointPtr result(EC_POINT_new(group()));
    const EC_POINT* blind = client ? point_m() : point_n();
    if (!result || EC_POINT_mul(group(), result.get(), impl_->scalar.get(), blind, impl_->password.get(), ctx.get()) != 1) {
        fail("вычисление точки");
    }
    message_ = encode_point(result.get(), ctx.get());
}

Spake2::~Spake2() = default;

std::optional<SessionKeys> Spake2::finish(const uint8_t* peer, std::size_t size) const {
    if (size != POINT_SIZE) return std::nullopt;
    CtxPtr ctx(BN_CTX_new());
    PointPtr peer_point(EC_POINT_new(group()));
    // oct2point проверяет, что точка лежит на кривой
    if (!ctx || !peer_point || EC_POINT_oct2point(group(), peer_point.get(), peer, size, ctx.get()) != 1 ||
        EC_POINT_is_at_infinity(group(), peer_point.get())) {
        return std::nullopt;
    }

    // Снимаем маску пира: K = x*(Y - w*N)
    PointPtr unblinded(EC_POINT_dup(peer_point.get(), group()));
    PointPtr mask(EC_POINT_new(group()));
    const EC_POINT* peer_blind = client_ ? point_n() : point_m();
    if (!unblinded || !mask ||
        EC_POINT_mul(group(), mask.get(), nullptr, peer_blind, impl_->password.get(), ctx.get()) != 1 ||
        EC_POINT_invert(group(), mask.get(), ctx.get()) != 1 ||
        EC_POINT_add(group(), unblinded.get(), unblinded.get(), mask.get(), ctx.get()) != 1 ||
        EC_POINT_is_at_infinity(group(), unblinded.get())) {
        return std::nullopt;
    }
    PointPtr shared(EC_POINT_new(group()));
    if (!shared || EC_POINT_mul(group(), shared.get(), nullptr, unblinded.get(), impl_->scalar.get(), ctx.get()) != 1 ||
        EC_POINT_is_at_infinity(group(), shared.get())) {
        return std::nullopt;
    }

    // Весь протокол входит в ключ: любое вмешательство в сообщения его меняет
    constexpr std::string_view context = "quokka-spake2-v1";
    Bytes transcript;
    append_framed(transcript, reinterpret_cast<const uint8_t*>(context.data()), context.size());
    const uint8_t* client_message = client_ ? message_.data() : peer;
    const uint8_t* server_message = client_ ? peer : message_.data();
    append_framed(transcript, client_message, POINT_SIZE);
    append_framed(transcript, server_message, POINT_SIZE);
    const Bytes shared_bytes = encode_point(shared.get(), ctx.get());
    append_framed(transcript, shared_bytes.data(), shared_bytes.size());
    Bytes password(static_cast<std::size_t>(BN_num_bytes(impl_->password.get())));
    BN_bn2bin(impl_->password.get(), password.data());
    append_framed(transcript, password.data(), password.size());

    noise::Key root{};
    SHA256(transcript.data(), transcript.size(), root.data());
    OPENSSL_cleanse(password.data(), password.size());
    return SessionKeys{label_key(root, "encryption"), label_key(root, "confirm-client"), label_key(root, "confirm-server")};
}

std::array<uint8_t, CONFIRM_SIZE> confirmation(const noise::Key& key) {
    return label_key(key, "quokka-confirm");
}

bool confirmation_matches(const noise::Key& key, const uint8_t* value, std::size_t size) {
    const auto expected = confirmation(key);
    return size == expected.size() && CRYPTO_memcmp(expected.data(), value, size) == 0;
}

}
