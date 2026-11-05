# OPNsense agent capabilities

The OPNsense adapter declares platform `opnsense` and capability `remote.web`.
The shared protocol version is `proto/VERSION`; the request builder is packaged
beside agentctl. Enrollment handlers and the native UI are implemented, with
[scoped installed validation](../../deploy/validation-native-public-certificate.md).

`remote.web` permits an authenticated tunnel to the local HTTPS management UI.
It does not permit configuration download, configuration push, firewall changes,
or telemetry collection. The adapter also implements the versioned GUI certificate
and relay trust extensions; those bounded workflows do not grant general device
configuration authority. The local agent owns service integration and native
persistence; public protocol messages carry no device private key.

Shared schemas accept bounded future platform identifiers and capabilities. This
does not imply that OpenWrt, VyOS, or any other platform has an implemented agent.
