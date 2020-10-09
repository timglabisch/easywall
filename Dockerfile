# Dockerfile (tag: v3)
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractiveµ
ENV TZ=Europe/Berlin

# common packages
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    ca-certificates curl file \
    build-essential \
    software-properties-common \
    autoconf automake autotools-dev libtool xutils-dev && \
    rm -rf /var/lib/apt/lists/*

ENV SSL_VERSION=1.0.2s

RUN curl https://www.openssl.org/source/openssl-$SSL_VERSION.tar.gz -O && \
    tar -xzf openssl-$SSL_VERSION.tar.gz && \
    cd openssl-$SSL_VERSION && ./config && make depend && make install && \
    cd .. && rm -rf openssl-$SSL_VERSION*

ENV OPENSSL_LIB_DIR=/usr/local/ssl/lib \
    OPENSSL_INCLUDE_DIR=/usr/local/ssl/include \
    OPENSSL_STATIC=1

# install all 3 toolchains
RUN curl https://sh.rustup.rs -sSf | \
    sh -s -- --default-toolchain stable -y && \
    /root/.cargo/bin/rustup update beta && \
    /root/.cargo/bin/rustup update nightly

RUN LC_ALL=C.UTF-8 add-apt-repository ppa:ondrej/php && apt update && apt install -y \
    php7.4-xml \
    php7.4-fpm \
    php7.4-cli \
    php7.4-curl \
    php7.4-gd \
    php7.4-intl \
    php7.4-json \
    php7.4-mysql \
    php7.4-soap \
    php7.4-zip \
    php7.4-bcmath \
    php7.4-sqlite3 \
    php-ssh2 \
    php-apcu \
    php7.4-tidy \
    php7.4-redis \
    php7.4-dev

ADD docker/start.sh /start.sh

ENTRYPOINT ["/start.sh"]