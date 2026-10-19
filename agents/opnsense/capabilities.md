# OPNsense agent capabilities

The OPNsense adapter declares platform `opnsense` and capability `remote.web`.
The shared protocol version is `proto/VERSION`; the request builder is packaged
beside agentctl. Enrollment handlers and UI integration remain W4 work.

`remote.web` permits an authenticated tunnel to the local HTTPS management UI.
It does not permit configuration download, configuration push, firewall changes,
or telemetry collection. The local agent owns service integration and configuration
persistence; the server sees only protocol identity and bounded health fields.

Shared schemas accept bounded future platform identifiers and capabilities. This
does not imply that OpenWrt, VyOS, or any other platform has an implemented agent.
