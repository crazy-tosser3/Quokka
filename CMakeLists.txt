cmake_minimum_required(VERSION 4.2.3)
project(Quokka LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(QUOKKA_BUILD_TESTS "Собирать тесты" OFF)

find_package(Boost REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(msquic CONFIG REQUIRED)

set(QUOKKA_CORE_SOURCES
        src/core/aead.hpp
        src/core/config.hpp
        src/core/discovery.hpp
        src/core/discovery.cpp
        src/core/identity.hpp
        src/core/identity.cpp
        src/core/log.hpp
        src/core/log.cpp
        src/core/mesh_node.hpp
        src/core/mesh_node.cpp
        src/core/net_utils.hpp
        src/core/net_utils.cpp
        src/core/noise.hpp
        src/core/noise.cpp
        src/core/protocol.hpp
        src/core/quic_runtime.hpp
        src/core/quic_runtime.cpp
        src/core/quic_session.hpp
        src/core/quic_session.cpp
        src/core/quic_stream.hpp
        src/core/quic_stream.cpp
        src/core/routing.hpp
        src/core/routing.cpp
        src/core/secure_channel.hpp
        src/core/secure_channel.cpp
        src/core/stats.hpp
        src/core/tcp_bridge.hpp
        src/core/tcp_bridge.cpp
        src/core/udp_tunnel.hpp
        src/core/udp_tunnel.cpp
        src/app/app.hpp
        src/app/app.cpp
        src/app/cli.hpp
        src/app/cli.cpp
)

add_library(quokka_core STATIC ${QUOKKA_CORE_SOURCES})

target_include_directories(quokka_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

# Защита от типовых ошибок памяти в сетевом коде
target_compile_options(quokka_core PUBLIC -Wall -Wextra -fstack-protector-strong)
target_compile_definitions(quokka_core PUBLIC
        $<$<CONFIG:Release,RelWithDebInfo>:_FORTIFY_SOURCE=2>
        _LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST
        _GLIBCXX_ASSERTIONS
)

target_link_libraries(quokka_core PUBLIC
        Boost::headers
        Threads::Threads
        OpenSSL::Crypto
        msquic::msquic
)

add_executable(Quokka src/main.cpp)
target_link_libraries(Quokka PRIVATE quokka_core)
set_target_properties(Quokka PROPERTIES OUTPUT_NAME quokka)
install(TARGETS Quokka RUNTIME DESTINATION bin)

if(QUOKKA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
