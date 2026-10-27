FROM golang:1.26.10-bookworm@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51 AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-tags=frps,noweb
COPY server/.go-version ./
COPY deploy/images/frps/go.mod deploy/images/frps/go.sum ./
RUN test "$(go env GOVERSION)" = "go$(cat .go-version)" && go mod download
COPY deploy/images/licenses.go /licenses.go
COPY LICENSE NOTICE /out/licenses/
RUN go build -p 2 -trimpath -o /out/frps github.com/fatedier/frp/cmd/frps \
    && GOFLAGS="-p=2 -tags=frps,noweb" go run /licenses.go github.com/fatedier/frp/cmd/frps /out/licenses \
    && cp /usr/local/go/LICENSE /out/licenses/GO-LICENSE

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ENV TZ=UTC
COPY --from=build /out/frps /frps
COPY --from=build /out/licenses /licenses
USER 65532:65532
ENTRYPOINT ["/frps"]
