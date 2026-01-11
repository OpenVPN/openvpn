# Build OpenVPN from source
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libssl-dev \
    liblz4-dev \
    liblzo2-dev \
    libpam0g-dev \
    libcap-ng-dev \
    libnl-genl-3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN autoreconf -fvi && \
    ./configure --disable-systemd --disable-plugins && \
    make -j$(nproc)

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    liblz4-1 \
    liblzo2-2 \
    libcap-ng0 \
    libnl-genl-3-200 \
    iproute2 \
    iptables \
    netcat-openbsd \
    gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/src/openvpn/openvpn /usr/local/sbin/openvpn

# Copy default server config into the image
COPY tests/reload_push_options/configs/server.conf.default /etc/openvpn/server.conf.default

RUN mkdir -p /dev/net && \
    mknod /dev/net/tun c 10 200 || true
