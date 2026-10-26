# Use an existing host reverse proxy

Select external mode during fresh initialization:

```sh
sudo ./nethub init \
  --source-directory /srv/nethub \
  --directory /srv/nethub-deployment \
  --backup-directory /protected/nethub-backup \
  --console-host console.example.com \
  --device-domain router.example.com \
  --expected-address 203.0.113.10 \
  --proxy-mode external
```

The generated Compose bundle contains no Caddy service. It publishes the web
origin at `127.0.0.1:18080` and device API at `127.0.0.1:18081`; both remain HTTP.
Use `--web-port` and `--device-port` for unused alternative ports. The console
origin remains HTTPS, including secure cookies and same-origin request checks.
This choice does not change the relay's required TLS listener on 7000 or TLS
passthrough on 8443.

Use Linux Docker Engine 28 or newer with the default NAT bridge behavior. Docker
documents a localhost-publication isolation issue in older releases; do not use
this path with older engines, routed bridge gateway modes or customized direct
routing that exposes the containers. See [Docker's port-publishing documentation](https://docs.docker.com/engine/network/port-publishing/).
The host, its local processes and administrators remain trusted; loopback binding
does not isolate one local user from another.

Install the generated `external-Caddyfile.example` into an existing **host-network**
Caddy configuration, or reproduce its routing in the administrator's host proxy.
It is an example, never activated by NetHub. The existing proxy owns public
listeners, certificate issuance, renewal and reload. A proxy in an unrelated
container cannot reach the host's loopback origins; this configuration does not
support that topology by opening origin ports publicly.

For NGINX/OpenResty, use the equivalent locations inside the existing HTTPS
server. Retain its certificate and renewal configuration. Adjust loopback ports
if initialization used alternatives:

```nginx
location = /healthz { return 404; }
location ^~ /healthz/ { return 404; }
location = /api/v1/frp { return 404; }
location ^~ /api/v1/frp/ { return 404; }

location ^~ /api/v1/devices/ {
    proxy_set_header Host console.example.com;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass http://127.0.0.1:18081;
}

location / {
    proxy_set_header Host console.example.com;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass http://127.0.0.1:18080;
}
```

Overwrite client-supplied forwarding headers at the public proxy. The generated
web/authz commands trust exactly the deployment edge gateway `/32`, which is the
host proxy's peer after loopback publication. They do not trust all private
networks. Do not add another proxy/CDN without reviewing that trust boundary and
testing its actual source address. See [NGINX's header handling](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header).

After deployment, verify the public certificate/hostname, login and secure
session, device enrollment, private health/hook denial, and the recorded source
address with a forged incoming X-Forwarded-For header. Confirm origins are
unreachable through every non-loopback host address and from another machine.
The deployment CI exercises the generated bundle through an independent
host-network Caddy with explicit fixture TLS, including source-spoof rejection.
That fixture does not validate an administrator's NGINX configuration or prove
isolation for arbitrary host firewall/NAT settings.

OIDC callbacks at `/api/v1/console/oidc/<slug>/callback` contain authorization
codes and state in their query. If access logging is enabled, redact those
queries or exclude callback access logs; do not log request cookies or bodies.
NetHub redirects to a fixed clean URL with no-referrer and no-store responses.
See [SSO state and diagnostic boundaries](oidc-login.md).

This is a fresh-bundle option. Existing bundles keep their recorded proxy mode;
`init --resume` does not migrate a running bundle or rotate its authority. Stop
and review existing public services before deliberately changing ingress.
