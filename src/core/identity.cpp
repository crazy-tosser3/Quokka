#include "core/identity.hpp"

#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <system_error>

namespace identity {
namespace {

constexpr std::string_view INVITE_PREFIX = "quokka2";
constexpr std::string_view BASE32 = "0123456789abcdefghjkmnpqrstvwxyz";  // Crockford
constexpr std::size_t CHECKSUM_SIZE = 4;
constexpr char PKCS12_PASSWORD[] = "quokka";  // блоб живёт только в памяти процесса

constexpr char NODE_FILE[] = "node.secret";
constexpr char NODE_HEADER[] = "quokka-node-v1";
constexpr char INVITE_FILE[] = "network.invite";

template <class T, void (*Free)(T*)>
struct Deleter {
    void operator()(T* p) const { Free(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using X509Ptr = std::unique_ptr<X509, Deleter<X509, X509_free>>;
using NamePtr = std::unique_ptr<X509_NAME, Deleter<X509_NAME, X509_NAME_free>>;
using Pkcs12Ptr = std::unique_ptr<PKCS12, Deleter<PKCS12, PKCS12_free>>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, Deleter<EVP_MD_CTX, EVP_MD_CTX_free>>;
using KdfCtxPtr = std::unique_ptr<EVP_PKEY_CTX, Deleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;

[[noreturn]] void crypto_fail(const char* what) {
    throw std::runtime_error(std::string("Ошибка криптографии: ") + what);
}

template <std::size_t N>
std::array<uint8_t, N> random_bytes() {
    std::array<uint8_t, N> out;
    if (RAND_bytes(out.data(), static_cast<int>(N)) != 1) crypto_fail("RAND_bytes");
    return out;
}

// Разные ключи для разных целей из одного секрета (RFC 5869)
template <std::size_t N>
std::array<uint8_t, N> hkdf(const Secret& secret, std::string_view info) {
    constexpr std::string_view salt = "quokka/v1";
    std::array<uint8_t, N> out;
    std::size_t length = N;
    KdfCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx ||
        EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), reinterpret_cast<const unsigned char*>(salt.data()),
                                    static_cast<int>(salt.size())) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), secret.data(), static_cast<int>(secret.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), reinterpret_cast<const unsigned char*>(info.data()),
                                    static_cast<int>(info.size())) != 1 ||
        EVP_PKEY_derive(ctx.get(), out.data(), &length) != 1 || length != N) {
        crypto_fail("HKDF");
    }
    return out;
}

PkeyPtr key_from_seed(const Seed& seed) {
    PkeyPtr key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
    if (!key) crypto_fail("Ed25519");
    return key;
}

Pin pin_of_key(EVP_PKEY* key) {
    unsigned char* der = nullptr;
    const int length = i2d_PUBKEY(key, &der);
    if (length <= 0) crypto_fail("i2d_PUBKEY");
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der, static_cast<std::size_t>(length), digest);
    OPENSSL_free(der);
    Pin pin;
    std::memcpy(pin.data(), digest, pin.size());
    return pin;
}

std::array<uint8_t, CHECKSUM_SIZE> invite_checksum(const uint8_t* data, std::size_t length) {
    constexpr std::string_view domain = "quokka-invite-v2";
    Bytes input(domain.begin(), domain.end());
    input.insert(input.end(), data, data + length);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(input.data(), input.size(), digest);
    std::array<uint8_t, CHECKSUM_SIZE> out;
    std::memcpy(out.data(), digest, out.size());
    return out;
}

template <std::size_t N>
bool from_hex(std::string_view hex, std::array<uint8_t, N>& out) {
    if (hex.size() != N * 2) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < N; ++i) {
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

void ensure_dir(const std::filesystem::path& dir) {
    std::error_code ec;
    if (std::filesystem::exists(dir, ec)) return;
    std::filesystem::create_directories(dir, ec);
    if (ec) throw std::runtime_error("Не удалось создать " + dir.string() + ": " + ec.message());
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
}

// Как и ssh, отказываемся читать секрет, доступный кому-то ещё
std::optional<std::string> read_private_file(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return std::nullopt;
        throw std::runtime_error("Не удалось открыть " + path.string() + ": " + std::strerror(errno));
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != ::geteuid()) {
        ::close(fd);
        throw std::runtime_error(path.string() + ": файл должен принадлежать текущему пользователю");
    }
    if (st.st_mode & 077) {
        ::close(fd);
        throw std::runtime_error(path.string() + ": файл доступен другим пользователям. Исправьте: chmod 600 " +
                                 path.string());
    }
    std::string content(4096, '\0');
    const ssize_t got = ::read(fd, content.data(), content.size());
    ::close(fd);
    if (got < 0) throw std::runtime_error("Не удалось прочитать " + path.string());
    content.resize(static_cast<std::size_t>(got));
    return content;
}

// Атомарно: файл либо старый, либо новый целиком, и никогда не бывает виден с широкими правами
void write_private_file(const std::filesystem::path& path, std::string_view content) {
    ensure_dir(path.parent_path());
    const auto suffix = random_bytes<8>();
    const std::filesystem::path tmp = path.string() + "." + to_hex(suffix.data(), suffix.size());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) throw std::runtime_error("Не удалось создать " + tmp.string() + ": " + std::strerror(errno));
    const bool written = ::write(fd, content.data(), content.size()) == static_cast<ssize_t>(content.size());
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    if (!written || !synced || ::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw std::runtime_error("Не удалось записать " + path.string());
    }
}

}

std::string encode_invite(const Invite& invite) {
    std::array<uint8_t, sizeof(Secret) + CHECKSUM_SIZE> raw;
    std::memcpy(raw.data(), invite.secret.data(), sizeof(Secret));
    const auto checksum = invite_checksum(raw.data(), sizeof(Secret));
    std::memcpy(raw.data() + sizeof(Secret), checksum.data(), CHECKSUM_SIZE);

    std::string out(INVITE_PREFIX);
    uint32_t bits = 0;
    int bit_count = 0;
    for (const uint8_t byte : raw) {
        bits = (bits << 8) | byte;
        bit_count += 8;
        while (bit_count >= 5) {
            out += BASE32[(bits >> (bit_count - 5)) & 0x1F];
            bit_count -= 5;
        }
    }
    if (bit_count > 0) out += BASE32[(bits << (5 - bit_count)) & 0x1F];
    return out;
}

std::optional<Invite> decode_invite(std::string_view text) {
    // Терпим регистр, пробелы и дефисы: код часто копируют из мессенджера
    std::string clean;
    for (const char c : text) {
        if (c == ' ' || c == '-' || c == '\t' || c == '\n' || c == '\r') continue;
        clean += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }
    if (!clean.starts_with(INVITE_PREFIX)) return std::nullopt;
    clean.erase(0, INVITE_PREFIX.size());

    std::array<uint8_t, sizeof(Secret) + CHECKSUM_SIZE> raw;
    constexpr std::size_t expected_chars = (raw.size() * 8 + 4) / 5;
    if (clean.size() != expected_chars) return std::nullopt;

    uint32_t bits = 0;
    int bit_count = 0;
    std::size_t pos = 0;
    for (char c : clean) {
        if (c == 'i' || c == 'l') c = '1';
        if (c == 'o') c = '0';
        const auto value = BASE32.find(c);
        if (value == std::string_view::npos) return std::nullopt;
        bits = (bits << 5) | static_cast<uint32_t>(value);
        bit_count += 5;
        if (bit_count >= 8) {
            raw[pos++] = static_cast<uint8_t>(bits >> (bit_count - 8));
            bit_count -= 8;
        }
    }
    if ((bits & ((1u << bit_count) - 1)) != 0) return std::nullopt;

    const auto checksum = invite_checksum(raw.data(), sizeof(Secret));
    if (CRYPTO_memcmp(checksum.data(), raw.data() + sizeof(Secret), CHECKSUM_SIZE) != 0) {
        return std::nullopt;
    }

    Invite invite;
    std::memcpy(invite.secret.data(), raw.data(), sizeof(Secret));
    return invite;
}

Invite make_invite() {
    return Invite{random_bytes<16>()};
}

Bytes make_pkcs12(const Seed& seed) {
    PkeyPtr key = key_from_seed(seed);
    X509Ptr cert(X509_new());
    if (!cert) crypto_fail("X509_new");

    // Цепочка не проверяется, важен только ключ, поэтому содержимое сертификата формальное
    const auto serial = random_bytes<8>();
    uint64_t serial_value = 0;
    for (const uint8_t byte : serial) serial_value = (serial_value << 8) | byte;
    static constexpr long DAY = 24 * 60 * 60;
    NamePtr name(X509_NAME_new());
    if (!name) crypto_fail("X509_NAME_new");
    if (X509_set_version(cert.get(), 2) != 1 ||
        ASN1_INTEGER_set_int64(X509_get_serialNumber(cert.get()),
                               static_cast<int64_t>(serial_value >> 1)) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(cert.get()), -DAY) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3650 * DAY) ||
        X509_set_pubkey(cert.get(), key.get()) != 1 ||
        X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("quokka"), -1, -1, 0) != 1 ||
        X509_set_subject_name(cert.get(), name.get()) != 1 ||
        X509_set_issuer_name(cert.get(), name.get()) != 1 ||
        X509_sign(cert.get(), key.get(), nullptr) == 0) {
        crypto_fail("создание сертификата");
    }

    Pkcs12Ptr p12(PKCS12_create(PKCS12_PASSWORD, "quokka", key.get(), cert.get(), nullptr,
                                0, 0, 0, 0, 0));
    if (!p12) crypto_fail("PKCS12_create");
    unsigned char* der = nullptr;
    const int length = i2d_PKCS12(p12.get(), &der);
    if (length <= 0) crypto_fail("i2d_PKCS12");
    Bytes out(der, der + length);
    OPENSSL_free(der);
    return out;
}

Pin pin_of_seed(const Seed& seed) {
    return pin_of_key(key_from_seed(seed).get());
}

std::optional<Pin> pin_of_certificate(const uint8_t* der, std::size_t length) {
    if (!der || length == 0 || length > 64 * 1024) return std::nullopt;
    const unsigned char* cursor = der;
    X509Ptr cert(d2i_X509(nullptr, &cursor, static_cast<long>(length)));
    if (!cert) return std::nullopt;
    EVP_PKEY* key = X509_get0_pubkey(cert.get());
    if (!key || EVP_PKEY_id(key) != EVP_PKEY_ED25519) return std::nullopt;
    return pin_of_key(key);
}

NetworkKeys network_keys(const Invite& invite) {
    const Seed link_seed = hkdf<32>(invite.secret, "link-key");
    NetworkKeys keys;
    keys.pkcs12 = make_pkcs12(link_seed);
    keys.link_pin = pin_of_seed(link_seed);
    keys.discovery_key = hkdf<32>(invite.secret, "discovery-key");
    return keys;
}

NodeId node_id_of(const PublicKey& key) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(key.data(), key.size(), digest);
    NodeId id;
    std::memcpy(id.data(), digest, id.size());
    return id;
}

NodeIdentity identity_from_keys(const Seed& signing_seed, const noise::Key& static_secret) {
    NodeIdentity node;
    node.signing_seed = signing_seed;
    PkeyPtr key = key_from_seed(signing_seed);
    std::size_t size = node.signing_public.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), node.signing_public.data(), &size) != 1) crypto_fail("Ed25519");
    node.static_key = noise::keypair_from_secret(static_secret);
    node.id = node_id_of(node.signing_public);
    return node;
}

NodeIdentity generate_identity() {
    return identity_from_keys(random_bytes<32>(), random_bytes<32>());
}

Signature sign(const NodeIdentity& node, const uint8_t* data, std::size_t size) {
    PkeyPtr key = key_from_seed(node.signing_seed);
    MdCtxPtr ctx(EVP_MD_CTX_new());
    Signature signature;
    std::size_t length = signature.size();
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
        EVP_DigestSign(ctx.get(), signature.data(), &length, data, size) != 1) {
        crypto_fail("подпись");
    }
    return signature;
}

bool verify(const PublicKey& public_key, const uint8_t* data, std::size_t size, const Signature& signature) {
    PkeyPtr key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size()));
    MdCtxPtr ctx(EVP_MD_CTX_new());
    return key && ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1 &&
           EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), data, size) == 1;
}

std::string to_hex(const uint8_t* data, std::size_t length) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    out.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0xF];
    }
    return out;
}

std::string short_id(const NodeId& id) {
    return to_hex(id.data(), 4);
}

std::filesystem::path state_dir() {
    if (const char* custom = std::getenv("QUOKKA_HOME"); custom && *custom) return custom;
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg) {
        return std::filesystem::path(xdg) / "quokka";
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return std::filesystem::path(home) / ".config" / "quokka";
    }
    throw std::runtime_error("Не удалось определить домашнюю папку: задайте QUOKKA_HOME");
}

NodeIdentity load_or_create_identity(const std::filesystem::path& dir) {
    const auto path = dir / NODE_FILE;
    if (const auto content = read_private_file(path)) {
        // Формат: заголовок, ключ подписи и статический ключ в hex, по одному в строке
        const std::string_view text = *content;
        const std::size_t first = text.find('\n');
        const std::size_t second = first == text.npos ? text.npos : text.find('\n', first + 1);
        const std::size_t third = second == text.npos ? text.npos : text.find('\n', second + 1);
        Seed seed;
        noise::Key static_secret;
        if (third == text.npos || text.substr(0, first) != NODE_HEADER ||
            !from_hex(text.substr(first + 1, second - first - 1), seed) ||
            !from_hex(text.substr(second + 1, third - second - 1), static_secret)) {
            throw std::runtime_error(path.string() + " повреждён. Удалите его: узел получит новую личность");
        }
        return identity_from_keys(seed, static_secret);
    }

    const Seed seed = random_bytes<32>();
    const noise::Key static_secret = random_bytes<32>();
    std::string text(NODE_HEADER);
    text += '\n' + to_hex(seed.data(), seed.size());
    text += '\n' + to_hex(static_secret.data(), static_secret.size()) + '\n';
    write_private_file(path, text);
    return identity_from_keys(seed, static_secret);
}

std::optional<Invite> load_saved_invite(const std::filesystem::path& dir) {
    const auto content = read_private_file(dir / INVITE_FILE);
    if (!content) return std::nullopt;
    return decode_invite(*content);
}

void save_invite(const std::filesystem::path& dir, const Invite& invite) {
    write_private_file(dir / INVITE_FILE, encode_invite(invite) + "\n");
}

}
