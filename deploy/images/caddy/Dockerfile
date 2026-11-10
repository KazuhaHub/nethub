FROM golang:1.26.10-bookworm@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51 AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local
COPY server/.go-version ./
COPY deploy/images/caddy/go.mod deploy/images/caddy/go.sum ./
RUN test "$(go env GOVERSION)" = "go$(cat .go-version)" && go mod download
COPY deploy/images/caddy/main.go deploy/images/caddy/jose_test.go ./
COPY deploy/images/caddy/prepare-jose.go ./
COPY deploy/images/licenses.go /licenses.go
COPY LICENSE NOTICE /out/licenses/
RUN go run prepare-jose.go /out/caddy-source \
    && (cd /out/caddy-source && GOFLAGS=-mod=vendor go build -p 2 -trimpath -ldflags="-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=v2.11.9-nethub.1" -o /out/caddy .) \
    && GOFLAGS=-p=2 go run /licenses.go . /out/licenses \
    && cp /usr/local/go/LICENSE /out/licenses/GO-LICENSE
COPY deploy/images/caddy/README.md /out/licenses/compatibility-notice.md

FROM caddy:2.11.9@sha256:0c2243efcf437ab7f7a978f1027fcf0d4f9be8a75df27b1b3fbc5dbe0ffa8cf0
RUN apk add --no-cache --upgrade brotli-libs=1.2.1-r0 curl=8.23.0-r0 libcurl=8.23.0-r0 zlib=1.4-r0 musl=1.2.5-r24 musl-utils=1.2.5-r24 \
    && chown 0:0 /config /config/caddy /data /data/caddy \
    && chmod 0700 /config /config/caddy /data /data/caddy
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/licenses /usr/share/licenses/nethub-caddy
