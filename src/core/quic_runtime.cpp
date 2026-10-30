#include "core/quic_runtime.hpp"

#include "core/protocol.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace quic {

const QUIC_API_TABLE* api = nullptr;
HQUIC registration = nullptr;
HQUIC client_configuration = nullptr;
HQUIC server_configuration = nullptr;

namespace {

constexpr char PKCS12_PASSWORD[] = "quokka";

[[noreturn]] void fail(const char* what, QUIC_STATUS status) {
    std::ostringstream msg;
    msg << what << " failed: 0x" << std::hex << status;
    throw std::runtime_error(msg.str());
}

void close_all() {
    if (client_configuration) { api->ConfigurationClose(client_configuration); client_configuration = nullptr; }
    if (server_configuration) { api->ConfigurationClose(server_configuration); server_configuration = nullptr; }
    if (registration)  { api->RegistrationClose(registration);   registration = nullptr; }
    if (api)           { MsQuicClose(api);                       api = nullptr; }
}

}

const QUIC_BUFFER& alpn() {
    static const QUIC_BUFFER buffer = {
        sizeof(protocol::ALPN) - 1,
        reinterpret_cast<uint8_t*>(const_cast<char*>(protocol::ALPN))
    };
    return buffer;
}

Runtime::Runtime(const std::vector<uint8_t>& pkcs12) {
    if (api) throw std::runtime_error("MsQuic runtime is already initialized");

    try {
        QUIC_STATUS status = MsQuicOpen2(&api);
        if (QUIC_FAILED(status)) fail("MsQuicOpen2", status);

        const QUIC_REGISTRATION_CONFIG reg_config = {
            "quokka",
            QUIC_EXECUTION_PROFILE_LOW_LATENCY
        };
        status = api->RegistrationOpen(&reg_config, &registration);
        if (QUIC_FAILED(status)) fail("RegistrationOpen", status);

        QUIC_SETTINGS settings{};
        settings.IdleTimeoutMs = 15000;
        settings.IsSet.IdleTimeoutMs = TRUE;
        settings.KeepAliveIntervalMs = 3000;
        settings.IsSet.KeepAliveIntervalMs = TRUE;
        settings.HandshakeIdleTimeoutMs = 5000;
        settings.IsSet.HandshakeIdleTimeoutMs = TRUE;
        settings.DatagramReceiveEnabled = TRUE;
        settings.IsSet.DatagramReceiveEnabled = TRUE;
        // Возобновление сессий не нужно: каждое подключение проходит полную проверку ключа
        settings.ServerResumptionLevel = QUIC_SERVER_NO_RESUME;
        settings.IsSet.ServerResumptionLevel = TRUE;
        // Двунаправленные потоки — трафик сервисов и транзит, односторонний — управление соседством
        settings.PeerBidiStreamCount = 256;
        settings.IsSet.PeerBidiStreamCount = TRUE;
        settings.PeerUnidiStreamCount = 1;
        settings.IsSet.PeerUnidiStreamCount = TRUE;

        QUIC_CERTIFICATE_PKCS12 cert{};
        cert.Asn1Blob = pkcs12.data();
        cert.Asn1BlobLength = static_cast<uint32_t>(pkcs12.size());
        cert.PrivateKeyPassword = PKCS12_PASSWORD;

        // NO_CERTIFICATE_VALIDATION отключает только проверку цепочки до CA, которой у нас нет.
        // Членство в сети проверяется по ключу в QuicSession (PEER_CERTIFICATE_RECEIVED).
        QUIC_CREDENTIAL_CONFIG cred_config{};
        cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
        cred_config.CertificatePkcs12 = &cert;
        const auto common_flags = QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
                                  QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
                                  QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES;

        // Каждый узел и принимает, и устанавливает соединения, а роль в TLS задаётся конфигурацией
        const auto open_configuration = [&](HQUIC& configuration, QUIC_CREDENTIAL_FLAGS role_flag) {
            QUIC_STATUS result = api->ConfigurationOpen(
                registration, &alpn(), 1, &settings, sizeof(settings), nullptr, &configuration);
            if (QUIC_FAILED(result)) fail("ConfigurationOpen", result);
            cred_config.Flags = common_flags | role_flag;
            result = api->ConfigurationLoadCredential(configuration, &cred_config);
            if (QUIC_FAILED(result)) fail("ConfigurationLoadCredential", result);
        };
        open_configuration(client_configuration, QUIC_CREDENTIAL_FLAG_CLIENT);
        open_configuration(server_configuration, QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION);
    } catch (...) {
        close_all();
        throw;
    }
}

Runtime::~Runtime() {
    close_all();
}

QUIC_BUFFER* make_buffer(const void* data, std::size_t length) {
    auto* raw_mem = new uint8_t[sizeof(QUIC_BUFFER) + length];
    auto* buffer = reinterpret_cast<QUIC_BUFFER*>(raw_mem);
    buffer->Buffer = raw_mem + sizeof(QUIC_BUFFER);
    buffer->Length = static_cast<uint32_t>(length);
    std::memcpy(buffer->Buffer, data, length);
    return buffer;
}

void free_buffer(void* buffer) {
    delete[] static_cast<uint8_t*>(buffer);
}

}
