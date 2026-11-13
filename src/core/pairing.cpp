#include "core/pairing.hpp"

#include "core/log.hpp"
#include "core/net_utils.hpp"
#include "core/pake.hpp"
#include "core/protocol.hpp"
#include "core/quic_runtime.hpp"

#include <boost/asio.hpp>

#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <map>
#include <mutex>
#include <set>

namespace pairing {
namespace {

using Clock = std::chrono::steady_clock;

// Каждая попытка подключения списывается заранее, ещё до ответа: иначе атакующий получил бы
// материал для проверки догадки, не заплатив за неё. После успеха попытка возвращается.
constexpr int MAX_ATTEMPTS = 10;
constexpr std::size_t MAX_ACTIVE_CODES = 8;
constexpr std::size_t MAX_CONCURRENT = 8;
constexpr std::size_t MAX_FRAME = 1024;
constexpr auto CLIENT_TIMEOUT = std::chrono::seconds(8);

void write_frame(HQUIC stream, const std::vector<uint8_t>& body, QUIC_SEND_FLAGS flags, const QUIC_API_TABLE* api) {
    std::vector<uint8_t> frame{uint8_t(body.size() >> 8), uint8_t(body.size())};
    frame.insert(frame.end(), body.begin(), body.end());
    QUIC_BUFFER* buffer = quic::make_buffer(frame.data(), frame.size());
    if (QUIC_FAILED(api->StreamSend(stream, buffer, 1, flags, buffer))) quic::free_buffer(buffer);
}

// Вынимает из буфера готовые кадры. false: кадр слишком большой
template <class Fn>
bool read_frames(std::vector<uint8_t>& rx, Fn&& on_frame) {
    std::size_t offset = 0;
    while (rx.size() - offset >= 2) {
        const std::size_t size = (std::size_t(rx[offset]) << 8) | rx[offset + 1];
        if (size > MAX_FRAME) return false;
        if (rx.size() - offset < 2 + size) break;
        if (!on_frame(rx.data() + offset + 2, size)) return false;
        offset += 2 + size;
    }
    rx.erase(rx.begin(), rx.begin() + static_cast<std::ptrdiff_t>(offset));
    return true;
}

}

struct Service::Shared {
    struct Code {
        Clock::time_point expires;
        unsigned uses{0};
        int attempts_left{MAX_ATTEMPTS};
    };

    identity::Invite network;
    mutable std::mutex mutex;
    std::map<std::string, Code> codes;
    std::atomic<std::size_t> connections{0};

    void purge(Clock::time_point now) {
        for (auto it = codes.begin(); it != codes.end();) {
            it = now >= it->second.expires ? codes.erase(it) : std::next(it);
        }
    }
};

namespace {

// Одно подключение нового устройства
struct ServerConnection {
    std::shared_ptr<Service::Shared> shared;
    HQUIC connection{nullptr};
    std::vector<uint8_t> rx;
    struct Offer {
        std::string code;
        pake::SessionKeys keys;
    };
    std::vector<Offer> offers;
    int step{0};
    bool done{false};

    bool on_client_point(HQUIC stream, const uint8_t* data, std::size_t size) {
        std::vector<std::string> candidates;
        {
            std::lock_guard<std::mutex> lock(shared->mutex);
            shared->purge(Clock::now());
            for (auto it = shared->codes.begin(); it != shared->codes.end();) {
                candidates.push_back(it->first);
                if (--it->second.attempts_left <= 0) {
                    logging::warn("[Безопасность] Код приглашения отозван: слишком много попыток входа");
                    it = shared->codes.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (candidates.empty()) return false;

        // Ответ на каждый действующий код: номер кода не раскрывается, а догадка у клиента одна
        std::vector<uint8_t> reply{static_cast<uint8_t>(candidates.size())};
        for (const std::string& code : candidates) {
            pake::Spake2 spake(false, code);
            const auto keys = spake.finish(data, size);
            if (!keys) return false;
            const auto confirm = pake::confirmation(keys->confirm_server);
            reply.insert(reply.end(), spake.message().begin(), spake.message().end());
            reply.insert(reply.end(), confirm.begin(), confirm.end());
            offers.push_back({code, *keys});
        }
        write_frame(stream, reply, QUIC_SEND_FLAG_NONE, quic::api);
        return true;
    }

    bool on_client_confirm(HQUIC stream, const uint8_t* data, std::size_t size) {
        if (size != 1 + pake::CONFIRM_SIZE || data[0] >= offers.size()) return false;
        const Offer& offer = offers[data[0]];
        if (!pake::confirmation_matches(offer.keys.confirm_client, data + 1, pake::CONFIRM_SIZE)) return false;

        identity::Secret secret;
        {
            std::lock_guard<std::mutex> lock(shared->mutex);
            const auto it = shared->codes.find(offer.code);
            if (it == shared->codes.end()) return false;  // исчерпан или истёк, пока шёл вход
            ++it->second.attempts_left;
            if (--it->second.uses == 0) shared->codes.erase(it);
            secret = shared->network.secret;
        }
        const auto cipher = noise::seal(offer.keys.encryption, 0, nullptr, 0, secret.data(), secret.size());
        write_frame(stream, cipher, QUIC_SEND_FLAG_FIN, quic::api);
        done = true;
        logging::info("[Сеть] Новое устройство вошло по коду приглашения");
        return true;
    }
};

QUIC_STATUS QUIC_API server_stream_callback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event) {
    auto* conn = static_cast<ServerConnection*>(context);
    switch (event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i) {
            const QUIC_BUFFER& buf = event->RECEIVE.Buffers[i];
            conn->rx.insert(conn->rx.end(), buf.Buffer, buf.Buffer + buf.Length);
        }
        const bool ok = read_frames(conn->rx, [&](const uint8_t* data, std::size_t size) {
            const int step = conn->step++;
            if (step == 0) return conn->on_client_point(stream, data, size);
            if (step == 1) return conn->on_client_confirm(stream, data, size);
            return false;
        });
        if (!ok) quic::api->ConnectionShutdown(conn->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, protocol::CLOSE_PROTOCOL_ERROR);
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        quic::free_buffer(event->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) quic::api->StreamClose(stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API server_connection_callback(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event) {
    auto* conn = static_cast<ServerConnection*>(context);
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        quic::api->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, reinterpret_cast<void*>(server_stream_callback), conn);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        --conn->shared->connections;
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) quic::api->ConnectionClose(connection);
        delete conn;
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

}

Service::Service(const identity::Invite& network) : shared_(std::make_shared<Shared>()) {
    shared_->network = network;
}

Service::~Service() = default;

Service::Issued Service::issue(std::chrono::seconds ttl, unsigned uses) {
    const std::string code = pake::generate_code();
    add(code, ttl, uses);
    return Issued{code, ttl, uses};
}

void Service::add(const std::string& code, std::chrono::seconds ttl, unsigned uses) {
    std::lock_guard<std::mutex> lock(shared_->mutex);
    const auto now = Clock::now();
    shared_->purge(now);
    while (shared_->codes.size() >= MAX_ACTIVE_CODES) {
        const auto oldest = std::min_element(shared_->codes.begin(), shared_->codes.end(), [](const auto& a, const auto& b) {
            return a.second.expires < b.second.expires;
        });
        shared_->codes.erase(oldest);
    }
    shared_->codes[code] = Shared::Code{now + ttl, uses, MAX_ATTEMPTS};
}

bool Service::active() const {
    std::lock_guard<std::mutex> lock(shared_->mutex);
    shared_->purge(Clock::now());
    return !shared_->codes.empty();
}

QUIC_STATUS Service::accept(HQUIC connection) {
    // Пока кодов нет, входа нет вообще: посторонний не заставит считать кривые
    if (!active() || shared_->connections.load() >= MAX_CONCURRENT) return QUIC_STATUS_CONNECTION_REFUSED;

    auto* conn = new ServerConnection{shared_, connection, {}, {}, 0, false};
    ++shared_->connections;
    quic::api->SetCallbackHandler(connection, reinterpret_cast<void*>(server_connection_callback), conn);
    const QUIC_STATUS status = quic::api->ConnectionSetConfiguration(connection, quic::pairing_configuration);
    if (QUIC_FAILED(status)) {
        --shared_->connections;
        delete conn;
    }
    return status;
}

QUIC_SETTINGS quic_settings() {
    QUIC_SETTINGS settings{};
    settings.IdleTimeoutMs = 10000;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.HandshakeIdleTimeoutMs = 5000;
    settings.IsSet.HandshakeIdleTimeoutMs = TRUE;
    settings.PeerBidiStreamCount = 1;
    settings.IsSet.PeerBidiStreamCount = TRUE;
    settings.PeerUnidiStreamCount = 0;
    settings.IsSet.PeerUnidiStreamCount = TRUE;
    settings.ServerResumptionLevel = QUIC_SERVER_NO_RESUME;
    settings.IsSet.ServerResumptionLevel = TRUE;
    return settings;
}

// --- Сторона нового устройства ---

namespace {

struct ClientState {
    const QUIC_API_TABLE* api{nullptr};
    std::string code;
    pake::Spake2 spake;
    HQUIC connection{nullptr};
    std::vector<uint8_t> rx;
    int step{0};
    std::optional<pake::SessionKeys> keys;

    std::mutex mutex;
    std::condition_variable cv;
    bool finished{false};
    bool closed{false};
    bool reached{false};
    Result result{Result::Unreachable};
    std::optional<identity::Invite> invite;

    explicit ClientState(const std::string& c) : code(c), spake(true, c) {}

    void complete(Result value) {
        std::lock_guard<std::mutex> lock(mutex);
        if (!finished) {
            finished = true;
            result = value;
        }
        cv.notify_all();
    }

    bool on_server_offers(HQUIC stream, const uint8_t* data, std::size_t size) {
        reached = true;
        constexpr std::size_t entry = pake::POINT_SIZE + pake::CONFIRM_SIZE;
        if (size < 1 || data[0] == 0 || size != 1 + data[0] * entry) return false;
        for (std::size_t i = 0; i < data[0]; ++i) {
            const uint8_t* cursor = data + 1 + i * entry;
            const auto candidate = spake.finish(cursor, pake::POINT_SIZE);
            if (!candidate || !pake::confirmation_matches(candidate->confirm_server, cursor + pake::POINT_SIZE, pake::CONFIRM_SIZE)) continue;
            keys = candidate;
            const auto confirm = pake::confirmation(keys->confirm_client);
            std::vector<uint8_t> reply{static_cast<uint8_t>(i)};
            reply.insert(reply.end(), confirm.begin(), confirm.end());
            write_frame(stream, reply, QUIC_SEND_FLAG_NONE, api);
            return true;
        }
        complete(Result::WrongCode);  // ни один код не совпал: догадок больше не шлём
        return false;
    }

    bool on_server_secret(const uint8_t* data, std::size_t size) {
        const auto plain = noise::open(keys->encryption, 0, nullptr, 0, data, size);
        if (!plain || plain->size() != sizeof(identity::Secret)) return false;
        identity::Invite received;
        std::copy(plain->begin(), plain->end(), received.secret.begin());
        {
            std::lock_guard<std::mutex> lock(mutex);
            invite = received;
        }
        complete(Result::Ok);
        return true;
    }
};

QUIC_STATUS QUIC_API client_stream_callback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event) {
    auto* state = static_cast<ClientState*>(context);
    switch (event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i) {
            const QUIC_BUFFER& buf = event->RECEIVE.Buffers[i];
            state->rx.insert(state->rx.end(), buf.Buffer, buf.Buffer + buf.Length);
        }
        const bool ok = read_frames(state->rx, [&](const uint8_t* data, std::size_t size) {
            const int step = state->step++;
            if (step == 0) return state->on_server_offers(stream, data, size);
            if (step == 1) return state->on_server_secret(data, size);
            return false;
        });
        if (!ok) state->complete(state->reached ? Result::WrongCode : Result::Unreachable);
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        quic::free_buffer(event->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) state->api->StreamClose(stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API client_connection_callback(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event) {
    auto* state = static_cast<ClientState*>(context);
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        HQUIC stream = nullptr;
        if (QUIC_FAILED(state->api->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE, client_stream_callback, state, &stream))) {
            state->complete(Result::Unreachable);
            break;
        }
        write_frame(stream, state->spake.message(), QUIC_SEND_FLAG_START, state->api);
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
        state->complete(state->reached ? Result::WrongCode : Result::Unreachable);
        std::lock_guard<std::mutex> lock(state->mutex);
        state->closed = true;
        state->cv.notify_all();
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

}

ClientOutcome join(const std::string& host, uint16_t port, const std::string& code) {
    ClientOutcome outcome;
    const QUIC_API_TABLE* api = nullptr;
    if (QUIC_FAILED(MsQuicOpen2(&api))) return outcome;
    const QUIC_REGISTRATION_CONFIG reg_config{"quokka-join", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    HQUIC registration = nullptr;
    HQUIC configuration = nullptr;
    HQUIC connection = nullptr;

    ClientState state(code);
    state.api = api;

    const QUIC_BUFFER alpn = quic::pairing_alpn();
    const QUIC_SETTINGS settings = quic_settings();
    QUIC_CREDENTIAL_CONFIG cred{};
    cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
    // Сертификат здесь ничего не доказывает: сторону подтверждает только знание кода в SPAKE2
    cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (QUIC_SUCCEEDED(api->RegistrationOpen(&reg_config, &registration)) &&
        QUIC_SUCCEEDED(api->ConfigurationOpen(registration, &alpn, 1, &settings, sizeof(settings), nullptr, &configuration)) &&
        QUIC_SUCCEEDED(api->ConfigurationLoadCredential(configuration, &cred)) &&
        QUIC_SUCCEEDED(api->ConnectionOpen(registration, client_connection_callback, &state, &connection))) {
        if (QUIC_SUCCEEDED(api->ConnectionStart(connection, configuration, QUIC_ADDRESS_FAMILY_INET, host.c_str(), port))) {
            std::unique_lock<std::mutex> lock(state.mutex);
            state.cv.wait_for(lock, CLIENT_TIMEOUT, [&] { return state.finished; });
            outcome.result = state.finished ? state.result : Result::Unreachable;
            outcome.invite = state.invite;
            lock.unlock();
            api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, protocol::CLOSE_NORMAL);
            lock.lock();
            state.cv.wait_for(lock, std::chrono::seconds(3), [&] { return state.closed; });
        }
        api->ConnectionClose(connection);
    }
    if (configuration) api->ConfigurationClose(configuration);
    if (registration) api->RegistrationClose(registration);
    MsQuicClose(api);
    return outcome;
}

std::vector<LanHost> find_on_lan(const std::string& multicast_ip, uint16_t discovery_port, std::chrono::seconds wait) {
    using boost::asio::ip::udp;
    boost::asio::io_context io;
    udp::socket socket(io);
    const udp::endpoint endpoint(boost::asio::ip::address_v4::any(), discovery_port);
    socket.open(endpoint.protocol());
    socket.set_option(udp::socket::reuse_address(true));
    const int one = 1;
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    socket.bind(endpoint);
    const auto group = boost::asio::ip::make_address(multicast_ip).to_v4();
    for (const auto& iface : local_ipv4_interfaces()) {
        boost::system::error_code ignored;
        socket.set_option(boost::asio::ip::multicast::join_group(group, iface), ignored);
    }

    std::vector<LanHost> found;
    std::set<std::string> seen;
    std::array<char, 64> buffer{};
    udp::endpoint sender;
    std::function<void()> receive = [&] {
        socket.async_receive_from(boost::asio::buffer(buffer), sender, [&](boost::system::error_code ec, std::size_t size) {
            if (ec) return;
            const auto port = protocol::decode_pairing_beacon(std::string(buffer.data(), size));
            if (port) {
                const std::string host = sender.address().to_string();
                if (seen.insert(host + ":" + std::to_string(*port)).second) found.push_back({host, *port});
            }
            receive();
        });
    };
    receive();
    io.run_for(wait);
    return found;
}

}
