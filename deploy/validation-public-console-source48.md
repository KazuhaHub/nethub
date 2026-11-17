# Public console verification on 2026-11-13

Source `d5c0d5fc4fb60a39c150a9e1b783321d3505a834` passed a real public
console browser trial using images from complete
[CI 43382960743](https://github.com/KazuhaHub/nethub/actions/runs/43382960743).
The deployment used a fresh private bundle and database on the approved shared
Linux host. This is not clean-host installation or independent operator acceptance.

The external host-network reverse proxy used the generated console and device
API routes to loopback origins. Its existing matching public certificate and key
were verified and copied privately. Automatic issuance was disabled for this
bounded trial; no CA account was adopted or created and no order was placed.
This does not establish certificate renewal.

The browser followed actual public DNS and HTTPS. Node independently verified the
hostname and chain against its bundled public roots; Chrome also verified TLS.
There was no fixture CA, certificate exception, destination override or proxy
shortcut. The served leaf matched the retained certificate.

The following checks passed:

- Public login and private health endpoint denial.
- Administrator login, secure HttpOnly host session and authenticated reload.
- Empty inventory, enrollment-token generation and dialog clearing.
- Exclusion of credentials and tokens from browser storage.
- Mobile viewport layout, logout and protected API rejection after logout.
- Zero CSP violations, browser errors and external requests.

Four actual screenshots were reviewed, with enrollment material masked. Raw
credentials, deployment identities and evidence remain outside Git. The mobile
viewport is not a phone or carrier-network sample.

Before interrupting the original listeners, an independent restore guard was
verified by process identity, start time, script hash and nonce. The trial had a
five-minute maximum and closed early. Both public replacements stopped before
the original OpenResty container restarted; the original Xray service also
recovered. Only the two owned public containers were removed. All 60 pre-existing
container identities and images remained; the other 59 container process/start/
finish/status records were unchanged. The private test backend remained healthy.

The companion approved 1 GiB OPNsense VM received the unsigned development plugin
0.0.19 after preserving its old package and native state. All 51 packaged source
files and the frpc binary matched the build record. Its desktop and mobile page
checks used the original login and an independently pinned private GUI leaf.
Unrelated native configuration, GUI identity and both security checks remained
unchanged. Fixed-footer clipping and the internal status scroll remain known
layout limits.

This trial did not enroll that appliance into the public deployment or measure
public Revoke. Native public enrollment/Open, the five-second cutoff, actual
mobile samples, reboot/Core restore, migration/rollback, independent operator
recovery, durable custody and formal release remain separate gates. The failed
installed runs remain failed; this record does not complete W5-W7.
