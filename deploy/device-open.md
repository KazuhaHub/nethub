# Opening a device

The inventory displays the assigned GUI hostname, installation report and validity
deadline. An authenticated device report means the device accepted a certificate;
it does not establish that a later browser connection reached that certificate.
The browser still checks the public chain and hostname normally.

Open is available for recently observed, unrevoked devices with a current,
host-matching installation report. Pending, unsupported, failed and expired
certificates do not enable it. The console reads only a tenant/owner-scoped
metadata projection; its runtime cannot read certificate chains, CSRs or reports.

An explicit click requests a 30-minute source-IP grant, then opens the assigned
HTTPS hostname on port 8443 in a detached tab. Repeating the click renews the
grant. Inventory polling and router traffic never renew it. A blocked popup gets
an explicit continuation link. Router navigation sends neither a console referrer
nor its host-only session cookie. A failed request closes the reserved blank tab.

The router requires its own login. After changing networks, click Open again.
If console and router traffic use different public source addresses (including
IPv4/IPv6 selection), the grant may not match; admission fails closed. The console
does not guess or automatically grant another source address.

Browser fixtures cover explicit renewal, pending/offline refusal, blocked popups,
failed requests, detached opener and cookie/referrer isolation under the production
CSP. PostgreSQL integration tests separately exercise installation metadata and
tenant/owner/runtime privilege boundaries. These fixtures do not replace native
public-network W5 acceptance or establish completion of W5-W7.
