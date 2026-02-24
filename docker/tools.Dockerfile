FROM rust:1.88-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ARG GO_VERSION=1.24.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bsdextrautils \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        iproute2 \
        iputils-ping \
        jq \
        libssl-dev \
        llvm \
        nghttp2-client \
        openssl \
        pkg-config \
        python3 \
        python3-pip \
        wrk \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) go_arch='amd64' ;; \
      arm64) go_arch='arm64' ;; \
      *) echo "unsupported architecture: ${arch}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" -o /tmp/go.tgz; \
    rm -rf /usr/local/go; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    ln -sf /usr/local/go/bin/go /usr/local/bin/go; \
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt; \
    rm -f /tmp/go.tgz

ENV GOBIN=/usr/local/bin
ENV PATH=/usr/local/go/bin:/usr/local/cargo/bin:${PATH}

RUN go install github.com/summerwind/h2spec/cmd/h2spec@latest \
    && go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest \
    && go install github.com/bojand/ghz/cmd/ghz@latest \
    && go install github.com/rakyll/hey@latest \
    && go install github.com/Shopify/toxiproxy/v2/cmd/cli@latest \
    && go install github.com/Shopify/toxiproxy/v2/cmd/server@latest \
    && mv /usr/local/bin/cli /usr/local/bin/toxiproxy-cli \
    && mv /usr/local/bin/server /usr/local/bin/toxiproxy-server

RUN cargo install cargo-fuzz --locked \
    && cargo install websocat --locked

RUN pip3 install --no-cache-dir --break-system-packages autobahntestsuite
RUN pip3 install --no-cache-dir --break-system-packages websocket-client
RUN pip3 install --no-cache-dir --break-system-packages mitmproxy

RUN printf '%s\n' 'export PATH=/usr/local/go/bin:/usr/local/cargo/bin:${PATH}' >/etc/profile.d/soth-mitm-tools-path.sh

RUN git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh \
    && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh

WORKDIR /workspace

CMD ["bash", "-c", "sleep infinity"]
