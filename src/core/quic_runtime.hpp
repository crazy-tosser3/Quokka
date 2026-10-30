#pragma once

#include <msquic.h>

#include <cstdint>
#include <string>
#include <vector>

namespace quic {

extern const QUIC_API_TABLE* api;
extern HQUIC registration;
extern HQUIC client_configuration;  // исходящие соединения
extern HQUIC server_configuration;  // входящие соединения

const QUIC_BUFFER& alpn();

class Runtime {
public:
    explicit Runtime(const std::vector<uint8_t>& pkcs12);
    ~Runtime();

    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
};

QUIC_BUFFER* make_buffer(const void* data, std::size_t length);
void free_buffer(void* buffer);

}
