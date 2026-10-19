FROM node:24.14.0-bookworm-slim@sha256:d8e448a56fc63242f70026718378bd4b00f8c82e78d20eefb199224a4d8e33d8 AS console
WORKDIR /src/server/web
COPY server/web/package.json server/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY server/web/ ./
RUN npm run build

FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
WORKDIR /src/server
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local
COPY server/go.mod server/go.sum server/.go-version ./
RUN test "$(go env GOVERSION)" = "go$(cat .go-version)" && go mod download
COPY server/ ./
COPY --from=console /src/server/internal/webui/dist ./internal/webui/dist
RUN go build -p 2 -trimpath -ldflags="-s -w" -o /out/nethub ./cmd/nethub
RUN cp /usr/local/go/LICENSE /out/GO-LICENSE

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/nethub /nethub
COPY LICENSE NOTICE /licenses/
COPY --from=build /out/GO-LICENSE /licenses/GO-LICENSE
USER 65532:65532
ENTRYPOINT ["/nethub"]
