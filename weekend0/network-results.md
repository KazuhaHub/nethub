# W0 experiment ④: external network results

Experiment ④ passed within the owner-approved two-mobile-network scope.
Kazuha explicitly cancelled further company/campus sampling after reviewing A/B
successes on 2026-10-17 (local date). That network class remains untested.
Experiments ⑤/⑥ and full W0 acceptance remain pending.

| Network | Port | TCP successes | TLS completions | HTTP 200 | Median TLS completion, seconds |
| --- | --- | --- | --- | --- | --- |
| A | 443 | 20/20 | 20/20 | 20/20 | 0.172636 |
| A | 8443 | 20/20 | 20/20 | 20/20 | 0.197043 |
| B | 443 | 20/20 | 20/20 | 20/20 | 0.307517 |
| B | 8443 | 20/20 | 20/20 | 20/20 | 0.284637 |

A/B identify two distinct mobile-carrier hotspots, as confirmed by the owner.
The Mac sampler alternated ports for 20 rounds per network using IPv4,
with proxy bypass requested. No carrier names or device metadata were required.
The owner supplied complete terminal tables; address columns were excluded from
private normalized CSVs. All 80 curl requests exited successfully.

The checked-in summary validator accepted both complete alternating samples.
Their timestamps fell within verified public-test windows, and each network's
20 tunneled requests correlated with 20 server NewUserConn hook requests.
Raw hook logs, endpoint details, and normalized samples remain outside Git.

The 8443 TCP success rate equalled the 443 rate on each measured network.
Neither the 20-percentage-point deficit nor zero-of-20 Q2 condition triggered.
This provides no measured reason to evaluate port sharing under Q2 for A/B;
D5 remains an owner decision. It does not establish company/campus reachability.
TLS completion timings include different backend paths and do not isolate
port-specific latency. B included a slow first request without connection failure.

The client was the NAT OPNsense guest on native Hyper-V with two vCPUs and the
owner-approved 1 GiB resource exception. Each window closed afterward; original
relay services/listeners were independently verified restored, test listeners
closed, and temporary baseline TLS key material removed.
