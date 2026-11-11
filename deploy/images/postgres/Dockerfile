FROM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local
COPY server/.go-version ./
COPY deploy/images/postgres/go.mod deploy/images/postgres/go.sum ./
RUN test "$(go env GOVERSION)" = "go$(cat .go-version)" && go mod download
COPY deploy/images/licenses.go /licenses.go
COPY LICENSE NOTICE /out/licenses/
RUN go build -p 2 -trimpath -ldflags="-s -w" -o /out/gosu github.com/tianon/gosu \
    && GOFLAGS=-p=2 go run /licenses.go github.com/tianon/gosu /out/licenses \
    && cp /usr/local/go/LICENSE /out/licenses/GO-LICENSE

FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
RUN apk add --no-cache --upgrade zlib=1.4-r0 musl=1.2.6-r3 musl-utils=1.2.6-r3 \
    krb5-libs=1.22.3-r0 libxslt=1.1.43-r4
COPY --from=build /out/gosu /usr/local/bin/gosu
COPY --from=build /out/licenses /usr/local/share/licenses/nethub-gosu
RUN test "$(id -u postgres)" = 70 && gosu postgres sh -c 'test "$(id -u)" = 70'
