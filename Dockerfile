FROM gcc:16.2.0-trixie AS dev

RUN apt-get update \
    && apt-get install --no-install-recommends -y clang-tidy cmake cppcheck doctest-dev ninja-build \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 1000 -g 1000 /build /workspace

USER 1000:1000
WORKDIR /workspace

FROM dev AS build
COPY --chown=1000:1000 CMakeLists.txt .
COPY --chown=1000:1000 src/ src/
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build /build --parallel 2

FROM ubuntu:26.04 AS test-routes
RUN apt-get update \
    && apt-get install --no-install-recommends -y iproute2 \
    && rm -rf /var/lib/apt/lists/*

FROM ubuntu:26.04 AS runtime
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade --no-install-recommends -y \
    && rm -rf /var/lib/apt/lists/* \
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} +

COPY --from=build --chown=0:0 --chmod=0555 /build/erikslund-mmproxy /opt/mmproxy/bin/

ENTRYPOINT ["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--inh-caps=-all,+net_raw", "--ambient-caps=-all,+net_raw", "--bounding-set=-all,+net_raw", "/opt/mmproxy/bin/erikslund-mmproxy"]
