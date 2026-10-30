ARG DEBIAN_VERSION=trixie

FROM debian:${DEBIAN_VERSION}-slim AS toolchain
ARG TARGETARCH
ARG CMAKE_VERSION=4.2.3

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential g++ ninja-build git ca-certificates curl patchelf \
        libboost-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
        amd64) CMAKE_ARCH=x86_64 ;; \
        arm64) CMAKE_ARCH=aarch64 ;; \
        *) echo "Unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.tar.gz" \
    | tar -xz -C /opt \
 && ln -s "/opt/cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}/bin/"* /usr/local/bin/ \
 && cmake --version

FROM toolchain AS msquic
ARG MSQUIC_VERSION=v2.6.3

RUN git clone --depth 1 --branch "${MSQUIC_VERSION}" https://github.com/microsoft/msquic.git /src/msquic \
 && cmake -S /src/msquic -B /src/msquic/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/msquic \
        -DQUIC_TLS_LIB=openssl \
        -DQUIC_USE_EXTERNAL_OPENSSL=ON \
        -DQUIC_BUILD_SHARED=ON \
        -DQUIC_BUILD_TEST=OFF \
        -DQUIC_BUILD_TOOLS=OFF \
        -DQUIC_BUILD_PERF=OFF \
        -DQUIC_ENABLE_LOGGING=OFF \
        -DQUIC_EMBED_GIT_HASH=OFF \
 && cmake --build /src/msquic/build \
 && cmake --install /src/msquic/build \
 && rm -rf /src/msquic

FROM toolchain AS build
ARG BUILD_TYPE=Release

COPY --from=msquic /opt/msquic /opt/msquic

WORKDIR /src/quokka
COPY CMakeLists.txt ./
COPY src ./src
COPY tests ./tests

RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        -DCMAKE_PREFIX_PATH=/opt/msquic \
 && cmake --build build \
 && mkdir -p /out \
 && cp build/quokka /out/ \
 && cp -P /opt/msquic/lib/libmsquic.so* /out/ \
 && strip /out/quokka \
 && patchelf --set-rpath '$ORIGIN' /out/quokka \
 && ldd /out/quokka

# Тесты на Linux: docker build --target test .
FROM build AS test
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 procps \
 && rm -rf /var/lib/apt/lists/* \
 && cmake -S . -B build-test -G Ninja \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        -DCMAKE_PREFIX_PATH=/opt/msquic \
        -DQUOKKA_BUILD_TESTS=ON \
 && cmake --build build-test \
 && LD_LIBRARY_PATH=/opt/msquic/lib ctest --test-dir build-test --output-on-failure

FROM scratch AS export
COPY --from=build /out/ /

FROM debian:${DEBIAN_VERSION}-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 libstdc++6 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /opt/quokka/
RUN ln -s /opt/quokka/quokka /usr/local/bin/quokka \
 && useradd --system --no-create-home quokka \
 && mkdir -m 700 /data \
 && chown quokka /data

# Личность point и сохранённый код живут в томе, чтобы переживать пересоздание контейнера
ENV QUOKKA_HOME=/data
VOLUME /data
USER quokka
WORKDIR /data
ENTRYPOINT ["quokka"]
