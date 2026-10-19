FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
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
COPY --from=build /out/gosu /usr/local/bin/gosu
COPY --from=build /out/licenses /usr/local/share/licenses/nethub-gosu
RUN test "$(id -u postgres)" = 70 && gosu postgres sh -c 'test "$(id -u)" = 70'
