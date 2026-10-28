FROM node:24.14.0-bookworm-slim@sha256:d8e448a56fc63242f70026718378bd4b00f8c82e78d20eefb199224a4d8e33d8 AS console
WORKDIR /src/server/web
COPY server/web/package.json server/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY server/web/ ./
RUN npm run build

FROM golang:1.26.10-bookworm@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51 AS build
WORKDIR /src/server
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local
COPY server/go.mod server/go.sum server/.go-version ./
RUN test "$(go env GOVERSION)" = "go$(cat .go-version)" && go mod download
COPY server/ ./
COPY --from=console /src/server/internal/webui/dist ./internal/webui/dist
RUN go build -p 2 -trimpath -ldflags="-s -w" -o /out/nethub ./cmd/nethub
RUN cp /usr/local/go/LICENSE /out/GO-LICENSE
RUN set -eu; mkdir -p /out/oidc-licenses; \
    for module in github.com/KazuhaHub/authcore github.com/coreos/go-oidc/v3 github.com/go-jose/go-jose/v4 golang.org/x/oauth2 github.com/fatedier/yamux; do \
      directory="$(go list -m -f '{{.Dir}}' "$module")"; \
      label="$(printf '%s' "$module" | tr / _)"; \
      cp "$directory/LICENSE" "/out/oidc-licenses/$label-LICENSE"; \
      if [ -f "$directory/NOTICE" ]; then cp "$directory/NOTICE" "/out/oidc-licenses/$label-NOTICE"; fi; \
      go list -m "$module" >> /out/oidc-licenses/MODULES; \
    done

FROM build AS http01-tests-build
RUN go test -c -o /out/http01.test ./internal/http01

FROM scratch AS http01-acceptance
COPY --from=http01-tests-build /out/http01.test /http01.test
COPY --from=build /out/nethub /nethub

FROM build AS guiacme-tests-build
RUN go test -c -o /out/guiacme.test ./internal/guiacme

FROM scratch AS guiacme-acceptance
COPY --from=guiacme-tests-build /out/guiacme.test /guiacme.test

FROM build AS guiissuer-tests-build
RUN go test -c -o /out/guiissuer.test ./internal/guiissuer

FROM scratch AS guiissuer-acceptance
COPY --from=guiissuer-tests-build /out/guiissuer.test /guiissuer.test

FROM build AS setup-tests-build
RUN go test -c -o /out/setup.test ./internal/setup

FROM scratch AS setup-acceptance
COPY --from=setup-tests-build /out/setup.test /setup.test

FROM build AS oidc-fixture-build
RUN go build -p 2 -trimpath -o /out/oidcfixture ./tests/oidcfixture

FROM scratch AS oidc-acceptance
COPY --from=oidc-fixture-build /out/oidcfixture /oidcfixture

FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea AS backup-tools
RUN test -s /etc/ssl/certs/ca-certificates.crt \
    && mkdir -p /out/backups /out/runtime \
    && chmod 0700 /out/backups /out/runtime

FROM scratch AS backup
COPY --from=backup-tools /lib /lib
COPY --from=backup-tools /usr/lib /usr/lib
COPY --from=backup-tools /usr/local/lib /usr/local/lib
COPY --from=backup-tools /usr/share /usr/share
COPY --from=backup-tools /usr/local/share /usr/local/share
COPY --from=backup-tools /etc/ssl /etc/ssl
COPY --from=backup-tools /etc/alpine-release /etc/alpine-release
COPY --from=backup-tools /etc/os-release /etc/os-release
COPY --from=backup-tools /usr/local/bin/pg_dump /usr/local/bin/pg_dump
COPY --from=backup-tools /usr/local/bin/pg_restore /usr/local/bin/pg_restore
COPY --from=backup-tools --chown=65532:65532 --chmod=0700 /out/backups /var/lib/nethub-backups
COPY --from=backup-tools --chown=65532:65532 --chmod=0700 /out/runtime /run/nethub-backup
COPY deploy/images/backup/passwd /etc/passwd
COPY deploy/images/backup/group /etc/group
COPY --from=build /out/nethub /nethub
COPY LICENSE NOTICE /licenses/
COPY --from=build /out/GO-LICENSE /licenses/GO-LICENSE
COPY --from=build /out/oidc-licenses /licenses/oidc/
ENV TZ=UTC PATH=/usr/local/bin:/usr/bin:/bin
USER 65532:65532
ENTRYPOINT ["/nethub"]
CMD ["backup", "serve"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=11m --retries=3 CMD ["/nethub", "backup", "health"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/nethub /nethub
COPY LICENSE NOTICE /licenses/
COPY --from=build /out/GO-LICENSE /licenses/GO-LICENSE
COPY --from=build /out/oidc-licenses /licenses/oidc/
USER 65532:65532
ENTRYPOINT ["/nethub"]
