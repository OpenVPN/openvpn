FROM ubuntu:18.04

RUN apt-get update -qq && apt-get install -y \
      automake \
      build-essential \
      git \
      liblz4-dev \
      liblzo2-dev \
      libpam0g-dev \
      libssl-dev \
      libtool \
      pkg-config \
      wget

WORKDIR /usr/src/openvpn
COPY . /usr/src/openvpn

ENV SSLLIB="openssl" \
    OPENSSL_VERSION="1.1.1c" \
    TRAVIS_OS_NAME="linux" \
    PREFIX="/usr/local" \
    JOBS="1"
RUN .travis/build-deps.sh && \
    .travis/build-check.sh
