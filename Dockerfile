FROM golang:1.26.5-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/nettle .

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
