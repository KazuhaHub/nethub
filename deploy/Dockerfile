FROM node:24.14.0-bookworm-slim@sha256:d8e448a56fc63242f70026718378bd4b00f8c82e78d20eefb199224a4d8e33d8 AS console
WORKDIR /src/server/web
COPY server/web/package.json server/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY server/web/ ./
RUN npm run build

FROM golang:1.26.0-bookworm@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c AS build
WORKDIR /src/server
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
COPY --from=console /src/server/internal/webui/dist ./internal/webui/dist
RUN go build -p 2 -trimpath -ldflags="-s -w" -o /out/nethub ./cmd/nethub

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/nethub /nethub
COPY LICENSE NOTICE /licenses/
USER 65532:65532
ENTRYPOINT ["/nethub"]
