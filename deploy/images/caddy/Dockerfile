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
    && (cd /out/caddy-source && GOFLAGS=-mod=vendor go build -p 2 -trimpath -ldflags="-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=v2.11.7-nethub.2" -o /out/caddy .) \
    && GOFLAGS=-p=2 go run /licenses.go . /out/licenses \
    && cp /usr/local/go/LICENSE /out/licenses/GO-LICENSE
COPY deploy/images/caddy/README.md /out/licenses/compatibility-notice.md

FROM caddy:2.11.7@sha256:685ae3d7c34d9b5f8caeddc5d14051db7bbd88ff1f5a2fa0c16bd8ca328fb7af
RUN apk add --no-cache --upgrade brotli-libs=1.2.1-r0 curl=8.23.0-r0 libcurl=8.23.0-r0
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/licenses /usr/share/licenses/nethub-caddy
