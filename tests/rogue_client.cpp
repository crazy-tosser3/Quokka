// Атакующий: QUIC-клиент, который не проходит наш протокол. Без кода не предъявляет сертификат,
// с кодом предъявляет ключ сети, но не представляется как узел. Пытается открыть поток.
//
//   quokka_rogue_client HOST PORT [INVITE]
//
// Код выхода: 0 — получен ответ (уязвимость), 1 — атака отбита.
#include "core/identity.hpp"
#include "core/protocol.hpp"

#include <msquic.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

namespace {

const QUIC_API_TABLE* api = nullptr;
std::atomic<bool> g_got_reply{false};
std::atomic<bool> g_shutdown{false};
std::atomic<HQUIC> g_connected{nullptr};

QUIC_STATUS QUIC_API stream_callback(HQUIC stream, void*, QUIC_STREAM_EVENT* event) {
    switch (event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        std::cout << "stream data from victim" << std::endl;
        g_got_reply = true;
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        api->StreamClose(stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API connection_callback(HQUIC connection, void*, QUIC_CONNECTION_EVENT* event) {
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        std::cout << "handshake finished on our side" << std::endl;
        g_connected = connection;
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        return QUIC_STATUS_NOT_SUPPORTED;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        std::cout << "rejected by transport, status 0x" << std::hex
                  << event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status << std::dec << std::endl;
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        g_shutdown = true;
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void attack(HQUIC connection) {
    HQUIC stream = nullptr;
    if (QUIC_FAILED(api->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE, stream_callback, nullptr, &stream))) return;
    // Заголовок, как у настоящего маршрутизируемого потока: dst/src не важны, узел должен отказать раньше
    static std::string payload(protocol::STREAM_HEADER_SIZE + 16, 'A');
    payload[0] = static_cast<char>(protocol::STREAM_VERSION);
    payload[1] = 8;
    static QUIC_BUFFER buffer{static_cast<uint32_t>(payload.size()), reinterpret_cast<uint8_t*>(payload.data())};
    if (QUIC_FAILED(api->StreamSend(stream, &buffer, 1, QUIC_SEND_FLAG_START, nullptr))) api->StreamClose(stream);
}

}

int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) {
        std::cerr << "usage: quokka_rogue_client HOST PORT [INVITE]\n";
        return 2;
    }
    const char* host = argv[1];
    const auto port = static_cast<uint16_t>(std::atoi(argv[2]));

    if (QUIC_FAILED(MsQuicOpen2(&api))) return 2;
    const QUIC_REGISTRATION_CONFIG reg_config{"rogue", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    HQUIC registration = nullptr;
    HQUIC configuration = nullptr;
    HQUIC connection = nullptr;
    if (QUIC_FAILED(api->RegistrationOpen(&reg_config, &registration))) return 2;

    std::string alpn_name = protocol::ALPN;
    const QUIC_BUFFER alpn{static_cast<uint32_t>(alpn_name.size()), reinterpret_cast<uint8_t*>(alpn_name.data())};
    QUIC_SETTINGS settings{};
    settings.IdleTimeoutMs = 3000;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.PeerUnidiStreamCount = 1;
    settings.IsSet.PeerUnidiStreamCount = TRUE;
    if (QUIC_FAILED(api->ConfigurationOpen(registration, &alpn, 1, &settings, sizeof(settings), nullptr, &configuration))) return 2;

    QUIC_CREDENTIAL_CONFIG cred{};
    cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
    cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    identity::Bytes pkcs12;
    QUIC_CERTIFICATE_PKCS12 cert{};
    if (argc == 4) {
        const auto invite = identity::decode_invite(argv[3]);
        if (!invite) return 2;
        pkcs12 = identity::network_keys(*invite).pkcs12;
        cert.Asn1Blob = pkcs12.data();
        cert.Asn1BlobLength = static_cast<uint32_t>(pkcs12.size());
        cert.PrivateKeyPassword = "quokka";
        cred.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
        cred.CertificatePkcs12 = &cert;
    }
    if (QUIC_FAILED(api->ConfigurationLoadCredential(configuration, &cred))) return 2;

    if (QUIC_FAILED(api->ConnectionOpen(registration, connection_callback, nullptr, &connection))) return 2;
    if (QUIC_FAILED(api->ConnectionStart(connection, configuration, QUIC_ADDRESS_FAMILY_INET, host, port))) return 2;

    const auto start = std::chrono::steady_clock::now();
    const auto deadline = start + std::chrono::seconds(6);
    bool attacked = false;
    while (std::chrono::steady_clock::now() < deadline && !g_shutdown && !g_got_reply) {
        if (!attacked && g_connected.load() && std::chrono::steady_clock::now() - start > std::chrono::milliseconds(500)) {
            attacked = true;
            attack(g_connected.load());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    const bool breached = g_got_reply;
    std::cout << (breached ? "BREACHED" : "repelled") << std::endl;
    std::_Exit(breached ? 0 : 1);
}
