FROM debian:bullseye

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install \
        wget \
        curl \
        nano \
        bash \
        net-tools \
        procps \
        iproute2 \
        coreutils \
        locales \
        gnutls-bin \
        screen && \
    locale-gen en_US.UTF-8

WORKDIR /server

# Grab the latest dat release binaries for Tethealla
RUN wget -q https://github.com/kotori/Tethealla/archive/refs/tags/dat.tar.gz && \
    tar zxf dat.tar.gz && \
    cp -ar Tethealla-dat/* . && \
    rm -rf Tethealla-dat && \
    rm dat.tar.gz

# Copy the overrides to configs and our own tools.
COPY . .

CMD ["./entrypoint.sh"]
