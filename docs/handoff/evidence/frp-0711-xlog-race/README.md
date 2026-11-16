# Bounded frp 0.71.1 logger diagnostic

This standalone library reproducer found a Go race between `AddPrefix`'s
prefix-string write and `Infof`'s read in the official checksummed frp 0.71.1
module. Go 1.26.11, `go mod verify` and one bounded race-detector run were used.
The test exited 1 because the detector reported the race; this is retained as a
positive diagnostic, never a passing product test. `result.json` records the
module/source/reproducer hashes and the complete private-log hash. The log
contains no NetHub configuration or credentials and is not a native run log.

The upstream logger documents that prefix operations are not thread safe. This
test deliberately overlaps a prefix update with a read; it does not establish
that a specific frpc execution made those calls concurrently. Source inspection
found that client login updates its context logger's run-ID prefix before the
previous control is closed, while control workers retain the context logger.
That is a hypothesis to investigate, not proof of the original failure.

No frpc process exit, packet loss, package migration or actual NetHub failure was
reproduced. In particular, this does not explain a Pong denial or prove that the
original a29 upgrade failed on the witness-process comparison. Native diagnostics
and original failed outcomes remain authoritative. No version pin, production
code, accepted deadline or invariant changed. The three frp pins stay 0.71.1.

To reproduce on an isolated Linux machine with Docker, copy only the three Go
files into a fresh writable directory and run from there:

```sh
docker run --rm --cpus 2 --memory 2g \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/diagnostic --workdir /diagnostic \
  --env GOTOOLCHAIN=local --env GOMAXPROCS=2 --env GOFLAGS=-p=2 \
  --env GOCACHE=/diagnostic/cache --env GOMODCACHE=/diagnostic/modules \
  --env CGO_ENABLED=1 \
  golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 \
  bash -c 'set -e; go version; go mod verify; go test -mod=readonly -race -count=1 -timeout 30s .'
```

Module retrieval uses public Go proxy/checksum services; the test opens no
listeners and uses no credentials. Keep downloaded modules/cache outside Git.
A different scheduling outcome is not a native acceptance result.

Primary source references:

- [Pinned logger implementation](https://github.com/fatedier/frp/blob/v0.71.1/pkg/util/xlog/xlog.go).
- [Client login and control replacement](https://github.com/fatedier/frp/blob/v0.71.1/client/service.go).
- [Control logger and workers](https://github.com/fatedier/frp/blob/v0.71.1/client/control.go).
