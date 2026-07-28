FROM golang:1.26.5-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN set -eu; \
    goos="${TARGETOS:-linux}"; \
    if [ -n "${TARGETARCH:-}" ]; then \
      CGO_ENABLED=0 GOOS="$goos" GOARCH="$TARGETARCH" go build -trimpath -ldflags="-s -w" -o /out/nettle .; \
    else \
      CGO_ENABLED=0 GOOS="$goos" go build -trimpath -ldflags="-s -w" -o /out/nettle .; \
    fi

FROM debian:bookworm-slim AS runtime

WORKDIR /app
COPY --from=build /out/nettle /usr/local/bin/nettle
COPY docker/Nettlefile /etc/nettle/Nettlefile
COPY docker/entrypoint.sh /usr/local/bin/nettle-entrypoint
RUN chmod +x /usr/local/bin/nettle-entrypoint

ENV NETTLE_CONFIG=/etc/nettle/Nettlefile

EXPOSE 1053/udp

ENTRYPOINT ["/usr/local/bin/nettle-entrypoint"]
CMD []
