FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local
COPY server/.go-version ./
COPY deploy/images/caddy/go.mod deploy/images/caddy/go.sum ./
RUN test "$(go env GOVERSION)" = "go$(cat .go-version)" && go mod download
COPY deploy/images/caddy/main.go ./
COPY deploy/images/licenses.go /licenses.go
COPY LICENSE NOTICE /out/licenses/
RUN go build -p 2 -trimpath -ldflags="-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=v2.11.7-nethub.1" -o /out/caddy . \
    && GOFLAGS=-p=2 go run /licenses.go . /out/licenses \
    && cp /usr/local/go/LICENSE /out/licenses/GO-LICENSE

FROM caddy:2.11.7@sha256:685ae3d7c34d9b5f8caeddc5d14051db7bbd88ff1f5a2fa0c16bd8ca328fb7af
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/licenses /usr/share/licenses/nethub-caddy
