# Weekend 0 传输层验证 RUNBOOK

## Supplemental VM boot preflight

The `W0 VM preflight` workflow boots the official 26.7 serial live image on a disposable Ubuntu runner. It checks KVM and memory first, validates the compressed image and the release signing key against the pinned upstream announcement, verifies the image signature, and waits for the guest login prompt.

The guest receives 3072 MiB, snapshot-only writes, and two restricted user-mode networks. No network bridge, published port, credentials, or NetHub package is configured. QEMU is terminated on completion or failure. The workflow uploads only a JSON summary and redacted serial output, retained for seven days.

Run it from GitHub Actions with **Run workflow**, or open a PR changing the preflight script/workflow. The first [verified boot](https://github.com/KazuhaHub/nethub/actions/runs/39026961946) reached the login prompt in 56 seconds after image verification.

This is preparation, not W0 acceptance. The live installer is not an installed, updated test device. The six experiments below still require the specified OPNsense version, public relay, DNS, and real external networks.

## Selected local NAT test topology

Kazuha clarified on 2026-10-17 that the current Windows machine hosts the OPNsense VM/client and the remote LXC runs the NetHub server/relay. Hyper-V installation and reboot completed, but guest startup at 3, 2, and 1.5 GiB failed with `0x8007000E`. Closing auxiliary windows was insufficient: the Hyper-V memory-balancer counter remained below 1 GiB available for guests. Increasing the Windows page file cannot supply its startup RAM; [Smart Paging](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/dynamic-memory) does not apply to starting a VM from the off state.

At Kazuha's request, QEMU TCG was initially used on the same Windows machine with 2 GiB pageable memory and a separate QCOW2 overlay over the verified image. Its WAN uses outbound user-mode NAT, and management forwards bind only to loopback. No public bridge or public inbound forwarding is configured. The WHPX investigation and current native Hyper-V diagnostic are described below. Preserve the existing disk; QEMU and the abandoned LXC guest are off.

The guest has booted and its management LAN is configured. The default root password was replaced; dedicated public-key SSH passed with its host key independently checked through the console. Local GUI HTTP form login and outbound HTTPS to the package mirror passed. Full template regeneration succeeded after the initial boot warning; its original cause has not been proven.

The stock minor firmware update from 26.7 and the subsequent reboot completed. OPNsense reports 26.7.7; the running kernel, installed kernel, and userland report FreeBSD 15.1-RELEASE-p4. Dedicated SSH passed with the same independently verified host key, and package-mirror HTTPS passed certificate verification after reboot. Earlier Chrome observations established widget containers and initial API responses, but did not prove periodic updates or full GUI usability. Mobile testing subsequently reported persistent loading; see the current blocker below. A disk snapshot is not a tested restore and does not contain a saved memory state. Record emulation and host paging when interpreting measurements; preparation overhead must not be presented as product throughput. Local NAT is not carrier CGNAT evidence; Kazuha confirmed availability of two mobile carriers and a company or campus network; A/B mobile comparison samples now pass; the owner explicitly waived company/campus sampling.

A subsequent bounded relay preflight returned the local NAT guest login form with a matching backend TLS leaf certificate. Both private configurations and the pinned FreeBSD frpc passed verification. Original relay listeners were rechecked after cleanup, and the restoration timer was cancelled. Those later desktop and mobile tests did not pass ①; the current native Hyper-V results follow below.

## GUI failure history and current native Hyper-V diagnostic

The observations above are preparation, not complete GUI acceptance. Public desktop testing found HTTP_REFERER rejection on login POST. Its error page contained a logout link, which was a false-positive intermediate authentication predicate. Adding only the test hostname through the stock Administration form removed the rejection; both DNS rebinding and HTTP_REFERER checks remain enabled. Dashboard containers and initial API responses then loaded, but subsequent mobile and WHPX desktop tests still stalled. The current native Hyper-V desktop result is recorded below. The short AJAX-count observation did not prove periodic widget updates. W0① was not accepted at that point; subsequent native Hyper-V testing now passes as recorded below.

TCG showed load averages near 29 and queued backend work, with free guest RAM and no guest swapping. The root cause is unproven. The owner-authorized Windows restart and WHPX capability check now pass. The existing overlay checksum matched the shutdown checkpoint. Earlier attempts ended through QMP before root mount after zero writes on every block device and process exits were checked. Disabling legacy VGA and parallel ports alone did not resolve startup; with the userspace interrupt controller, the existing guest reached its shell in about 15 minutes. That WHPX boot passed checks for dedicated public-key SSH with an unchanged host key, OPNsense 26.7.7, matching kernel and userland, and package-mirror TLS. A five-second sleep advanced guest wall and monotonic clocks by about five seconds; guest swap counters were zero. The calibration warning remains. The disk and NAT layout are preserved, with no TCG fallback. See the [QEMU WHPX prerequisites and debugging options](https://www.qemu.org/docs/master/system/whpx.html).

The full local GUI failed under WHPX. Later runs populated interface rows, charts, and EventSource messages, but system-information data and periodic clock updates did not pass; widget requests timed out. The failure reproduced without the public relay. A temporary CPU-affinity comparison did not resolve it; the original two-CPU mask was independently verified through the serial console afterward. The initial-wizard flag was cleared through the stock Abort button after console configuration. XML comparison confirmed that all other settings were preserved, excluding revision metadata; the test hostname and both security checks remain correct.

The 3 GiB, two-vCPU WHPX VirtIO profile booted in about nine minutes and passed SSH, version, mirror TLS, and clock checks, but complete GUI checks still failed. Checksum, TSO, and LRO offloading were already disabled. Sequential HTTP/2 and HTTP/1.1 API probes both succeeded; they did not establish a protocol-specific cause. A later host-CPU-model trial panicked in `devfs_find` and exited. Its failed state was preserved before restoring the preceding disk-only snapshot; the generic-CPU launcher was restored. The restored source QCOW2 has not been rebooted. Monitor serial output from each launch's recorded offset rather than treating older appended boot messages as current evidence.

The current native Hyper-V diagnostic uses a separate VHDX converted from that restored disk, with 1 GiB RAM and two vCPUs. Content comparison passed before and after clearing the host sparse-file flag required by Hyper-V. The converted copy booted successfully. Synthetic NICs were verified by pinned MAC; LAN was preserved and WAN was configured through the stock console for host NAT. Public-key SSH retained the verified host key. Current firmware/kernel/userland, package-mirror TLS, and five-second clock-progress checks passed with no guest swap activity. Local management forwards bind only to loopback. Complete local and public-relay desktop checks passed with the stock five-second widget timeout: system information, interface rows, charts, periodic clock updates, menu navigation, and no widget, request, HTTP, or page-script errors. Both GUI security checks remain enabled and the backend TLS leaf certificate matches through the relay. Original relay services/listeners were independently verified after cleanup, test listeners are closed, and the restoration timer was cancelled. The temporary credential page remains closed.

These 1 GiB desktop checks are preparation, not numbered W0 acceptance. On 2026-10-17, Kazuha explicitly approved continuing W0 at 1 GiB with the deviation from the [documented 3 GiB VM minimum](https://docs.opnsense.org/manual/virtuals.html) recorded in the report. Keep memory, swapping, and performance observations; do not generalize this environment to production sizing. Public desktop self-testing and mobile ① now pass. Experiments ②/③ also pass; ④ now passes within the owner-approved two-mobile-network scope. Experiment ⑤ now passes; ⑥ remains outstanding. No product implementation has started.


W0 progress (2026-10-17): experiment ① passed after the owner reported normal mobile login, Dashboard data, periodic refresh, menu navigation, and reload. Carrier, phone OS, and browser were left unrecorded at the owner's explicit request. The exact Alternate Hostnames entry was required; DNS rebinding and HTTP_REFERER checks remain enabled. Experiment ② passed using the fresh all-allow connection: Login metadata matches the configured top-level values, NewProxy `user.metas` matches Login, the requested subdomain matches, and the server-assigned NewProxy `user.run_id` is nonempty. The Login JSON omitted initial `client_id` and `run_id`. The control peer matched an independent connection through the same host NAT. See the [observed hook inputs](../proto/frp-hooks-0.71.0.md).

Experiment ③ passed six isolated fault groups: Login and NewProxy each with deny, HTTP 500, and a 120-second sleeping hook. Deny/500 prevented registration. The NewProxy sleeping request remained pending at 115 seconds while the frps admin API responded; heartbeat timeout was observed by the 35-second sample. Future requests were switched to allow at 110 seconds for recovery, without interrupting the existing sleep. At 125 seconds its delayed response had completed but the route was still unavailable; by 140 seconds registration and access had recovered. Login hang caused the client to exit and did not create a proxy after the delayed response. Restoring all allow recovered registration, access, and approximately ten-second heartbeats. Original relay services and listeners were independently verified after cleanup. These bounded observations found no fail-open and do not prove an infinite timeout.

Availability risk retained for review: a slow ownership hook blocks new registration; heartbeat timeout and control handoff can delay recovery even when frps itself remains responsive. Product hooks need bounded internal work and explicit failure handling. Decisions about NewUserConn/Ping gating and revocation latency still require ⑥ and the W0 review. Experiment ④ passes within the owner-approved two-mobile-network scope: A and B each returned TCP, TLS, and HTTP success in all 20 rounds on both ports, without triggering Q2. Company/campus sampling was explicitly waived by Kazuha and remains untested. See [the network report](network-results.md). Experiment ⑤ now passes; ⑥ remains pending. All results use the owner-approved 1 GiB exception, with no guest swapping in the recorded samples. Raw payloads, credentials, and deployment details stay outside the repository. W0 is not fully accepted and no product code has started.

Network scope exception (2026-10-17): after successful A/B samples from two distinct mobile carriers, Kazuha explicitly stopped further sampling. Company/campus coverage is untested and is not an acceptance gate for this run. See [the measured results](network-results.md). This exception does not change the Q2 thresholds.

Experiment ⑤ (2026-10-17): mobile source IPv4 matched NewUserConn remote_addr; proxy identity and device metadata matched registration. New connections were denied while the existing mobile Dashboard remained usable and control heartbeats stayed allowed. Desktop HTTP 500 and restored-allow checks passed. Original relay services were restored. See [the user-connection report](userconn-results.md). Experiment ⑥ remains pending.

## 这是什么、为什么要做

这是 NetHub 项目写第一行产品代码之前的第一步。目的只有一个：用真实的 frp
0.71.0 二进制，在真实网络环境下，回答下面六个问题。前四个任何一个答案和预期不符，
都会导致产品架构要重新想；第五个决定 DESIGN Q7 的缓解方案能不能做；第六个决定"撤销
设备"能不能真的把隧道断掉：

1. **穿透本身通不通**——CGNAT 后面的 OPNsense，能不能在不做端口转发的情况下被外部
   浏览器打开完整可用的 Web UI。这是产品能不能成立的地基。
2. **归属校验有没有抓手**——frps 的 `httpPlugins`（`Login`/`NewProxy`）能不能拿到
   "这是哪台设备 + 它想注册哪个域名"这两类信息，让控制面在**不碰设备 config.xml**
   的前提下做"这台设备只能用它自己的域名"的校验。这是安全模型的地基。
   如果答案是否定的，整个安全模型要重新设计——**这是本次验证里优先级最高的一项**。
3. **控制面挂了会怎样**——如果做归属校验的那个 httpPlugin 后端卡死或返回 500，
   frps 是拒绝新代理注册（fail-closed，更安全但控制面变成单点故障）还是照样放行
   （fail-open，可用性更好但校验形同虚设）。这条结论直接决定"控制面单点故障"这个
   风险在威胁模型里该打多高的分。
4. **在真实受限网络下好不好用**——运营商 4G/5G、公司网络这类不受我们控制的网络，
   对 8443 端口的连通性和稳定性如何，**跟同一台 VPS 上的 443 比差多少**。这决定要不要
   把 vhost-https 复用到 443（DESIGN Q2 的数据规则）。
5. **能不能在 frps 这一层挡住"知道域名的陌生人"**（DESIGN Q7）——SNI 透传之下，任何
   知道或猜到 `<subdomain>.<domain>:8443` 的人都能打开设备的 OPNsense 登录页，控制台的
   登录和 SSO 挡不在它前面。候选缓解是 frps 的 `NewUserConn` 插件钩子：它对 https
   vhost 代理是否触发、带的 `remote_addr` 是不是真实客户端 IP、拒绝能不能真的挡住连接，
   都要实测确认。
6. **撤销一台设备时，能不能把它已经在线的隧道断掉**——frps 0.71.0 的 admin API 只能
   列出、不能断开在线的客户端或代理（DESIGN §5）。候选主机制是"对已撤销设备的心跳
   `Ping` 返回拒绝"，配合 frpc 显式打开的应用层心跳。它能不能断、多快断、已打开的浏览器
   页面会不会跟着断、断开后设备能不能被 `Login` 挡在外面，以及它的代价——控制面一停，
   所有设备的隧道是不是都会在一个心跳间隔内被切断——都要实测。

> **先读这一条，①～⑤都受它影响。** 为了测⑥，`frps.toml` 订阅了 `Ping`，`frpc.toml`
> 显式打开了应用层心跳（每 10 秒一次）。所以从 frpc 连上那一刻起，**每 10 秒一次的 `Ping`
> 都要经过探针**：探针没起、正在重启、或者对 `Ping` 返回 deny / error500，按源码 frpc 会在约
> 10 秒内断开整条隧道（返回 hang 时约 30 秒），已打开的页面预计也会跟着断。因此：
>
> - 验收项①～⑤期间 `Ping` 必须保持 `allow`，探针必须一直在跑；
> - **运行中换模式一律用探针的模式文件（第 1.6 步），不要 Ctrl+C 重启探针**；只有在 frpc
>   已经停掉的时候重启探针才是安全的；
> - 如果在①～⑤里看到 frpc 莫名其妙地断开重连，先看探针日志里 `Ping` 那几条的模式是不是
>   `allow`、探针是不是被重启过，再怀疑别的。

本 RUNBOOK 默认你已经具备：

- 一台可以从公网访问的干净 VPS（本文用 `203.0.113.10` 占位），443 端口没有被别的
  服务占用（验收项④要临时在 443 上起一个基线监听）。
- 一个你控制 DNS 的域名（本文用 `example.com` 占位，实际需要给 `router.example.com`
  或你自己选的子域名加一条泛解析）。
- 一台可以临时 SSH 上去、装了 OPNsense 26.7.x（26.7.1_1 或更新）、能出网的测试机，
  它必须同时满足：
  - **不是生产路由器**。这台机器会被临时装上手工运行的 frpc，验证完要清理干净。
  - **Owner-approved packaging test host** (DESIGN decision #20, revised
    2026-10-17): Kazuha permits package building, signing, and NetHub use on
    this machine. Removing signing keys or build/signing scratch is no longer
    required before testing. Other signing hosts remain outside scope.
  - If using the earlier public packaging test device for a separate comparison, account for its differences from the selected NAT guest (PLAN §5.2):
    GUI 不在 443，第 2.3 步要把 `localPort` 改成它实际的 GUI 端口；它有公网 IP，
    GUI 端口在 WAN 上对外开放，做验收项①之前要把这条放行规则限制成只允许你自己的 IP，
    否则①证明不了"不开入站端口也能访问"，结果里也要写明它不在 NAT/CGNAT 后面。
  - 最好**同时装着 os-frp**：这样可以顺便提前看一眼两套 frpc
    能不能共存（本套件手工跑的 frpc 用的是 `/tmp` 下的独立二进制和配置，不碰 os-frp
    的 `/usr/local/sbin/frpc`、`/usr/local/etc/frp/frpc.toml`，也没有开 frpc 的
    `[webServer]`，不会去抢 os-frp 管理界面的 127.0.0.1:7400）。
- 一部能切到运营商 4G/5G 的手机（走真实的 CGNAT 路径），以及至少一个受限网络样本
  （公司/校园网络之类）。

所有命令里出现的 `203.0.113.10`、`example.com`、`router.example.com` 都要换成你
自己的真实值——它们是 RFC 5737 文档用 IP 和示例域名，本身解析不到任何东西。

---

## 第 0 步：下载并校验 frp 0.71.0 官方二进制

**不要用发行版仓库里的 frp 包，不要用别人转发的二进制。** 版本必须精确是
0.71.0（本套件所有配置字段都是照这个版本的源码核对的，差一个小版本字段名和语义
都可能不一样）。

**版本说明**：0.71.0 是刻意锁定的，跟打包仓库里 `os-frp` 锁的版本一致（截至
2026-10-16；DESIGN 决策 #19：frps/frpc 同版本）。frp v0.71.1 已经在 2026-10-14 发布，
发布说明里是控制连接写失败后卡住、重连、依赖更新之类的修复。对照 GitHub 上
v0.71.0...v0.71.1 的 compare（2026-10-16 查看）：`pkg/plugin/server/` 没有任何改动；
`pkg/config/v1/` 下 `client.go`、`server.go`、`proxy_plugin.go` 的改动都只是把
`lo.ToPtr(true)` 换成 `new(true)`，没有动字段名和 json tag；`server/proxy/proxy.go`
的改动在 `NewUserConn` 钩子之后的限速包装那一行，不涉及钩子本身。所以 Weekend 0 的
结论预计可以沿用到 0.71.1。**如果要升级，`os-frp`、以后 NetHub 插件里带的 frpc、
以及 frps 镜像必须一起升，不要只升一边**；这次验证本身仍然用 0.71.0。

### 0.1 确定你要下载的架构

- VPS（跑 `frps`）：先 `uname -m` 确认，常见 VPS 是 `x86_64` → 对应
  `frp_0.71.0_linux_amd64.tar.gz`；如果是 ARM VPS（比如某些云厂商的 Ampere
  实例）则是 `frp_0.71.0_linux_arm64.tar.gz`。
- OPNsense 测试机（跑 `frpc`）：OPNsense 是 FreeBSD，标准安装是 amd64，对应
  `frp_0.71.0_freebsd_amd64.tar.gz`。在 OPNsense 上执行 `uname -m` 确认一下，
  理论上应该是 `amd64`。

### 0.2 下载二进制和官方 checksum 文件

在 VPS 上：

```bash
cd /tmp
curl -LO https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz
curl -LO https://github.com/fatedier/frp/releases/download/v0.71.0/frp_sha256_checksums.txt
```

在 OPNsense 上（OPNsense 自带 `fetch`，不一定有 `curl`）：

```sh
cd /tmp
fetch https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_freebsd_amd64.tar.gz
fetch https://github.com/fatedier/frp/releases/download/v0.71.0/frp_sha256_checksums.txt
```

### 0.3 核对 sha256

`frp_sha256_checksums.txt` 里是所有平台二进制包的 sha256，一行一个，格式是
`<64位十六进制哈希>  <文件名>`。**不要在这份 RUNBOOK 里抄一个具体哈希值去比对**
——版本一致的话你直接从这个文件里 grep 出对应那一行，用工具自动比对，比人眼核对
一长串十六进制数字可靠得多：

Linux（VPS）上：

```bash
sha256sum --ignore-missing -c frp_sha256_checksums.txt
# 应该看到: frp_0.71.0_linux_amd64.tar.gz: OK
```

macOS 上（如果你从 Mac 下载后再传到 VPS）：

```bash
shasum -a 256 frp_0.71.0_linux_amd64.tar.gz
grep frp_0.71.0_linux_amd64.tar.gz frp_sha256_checksums.txt
# 两行的哈希值手动比对应该完全一致
```

FreeBSD（OPNsense）上没有 `sha256sum` 但有 `sha256`：

```sh
sha256 -c "$(grep freebsd_amd64 frp_sha256_checksums.txt | awk '{print $1}')" frp_0.71.0_freebsd_amd64.tar.gz
# 应该输出 (frp_0.71.0_freebsd_amd64.tar.gz) 后面跟 OK
```

**任何一步的哈希对不上，立刻停下**，重新下载，或者怀疑网络链路被中间人篡改，
不要用一个哈希校验失败的二进制继续做后面任何步骤。

### 0.4 解压

```bash
tar xzf frp_0.71.0_linux_amd64.tar.gz      # VPS，会解出 frp_0.71.0_linux_amd64/{frps,frpc,...}
tar xzf frp_0.71.0_freebsd_amd64.tar.gz    # OPNsense，同理
```

---

## 第 1 步：在一台干净 VPS 上起 frps

### 1.1 DNS 先配好

给 `router.example.com`（换成你自己的域名）加一条**泛解析记录**：

```
*.router.example.com.   A   203.0.113.10
```

（换成你 VPS 的真实公网 IP）。用 `dig` 确认生效（DNS 传播可能要几分钟到几十分钟，
取决于你的 DNS 服务商和 TTL）：

```bash
dig +short weekend0-test.router.example.com
# 应该直接输出 203.0.113.10（或者你的真实 IP）
```

### 1.2 防火墙放行端口

VPS 的安全组/防火墙需要放行：
- TCP 7000（frpc 连 frps 的控制通道，对应 `frps.toml` 里的 `bindPort`）
- TCP 8443（浏览器直接访问的 vhost-https 端口，对应 `vhostHTTPSPort`）
- TCP 443（**只在验收项④采样期间**放行，给同一台 VPS 上的 443 基线监听用；④做完
  就关掉，见附录清理清单）

`webServer`（7500）和探针 `probe.py`（9000）都绑定在 `127.0.0.1`，**不需要**、
也**不应该**对公网开放。

### 1.3 把这套套件的文件传到 VPS

把 `frps.toml`、`frpc.toml` 和 `probe.py` 传到 VPS 上同一个工作目录，和刚解压出来的
`frps`、`frpc` 二进制放在一起（或者把二进制加进 `PATH`）。`frpc.toml` 放这里只是为了
在第 1.5 步顺手做一次配置检查，真正运行 frpc 是在 OPNsense 上（第 2 步）。

### 1.4 改 frps.toml 里的占位值

- `[webServer]` 下的 `user` / `password` 两行是 `CHANGE_ME` 占位，**必须改掉再启动**。
  密码用 `openssl rand -base64 24` 生成一个一次性的。这两个值只写在 VPS 上这份
  `frps.toml` 里，不要回填进仓库。
- 如果打算加 `auth.token`：去掉 `frps.toml` 里那行 `# auth.token = ...` 的注释并填上
  随机串。它必须留在原来的位置（顶层，`[webServer]` 之前），不要挪到任何表头下面。
  `frpc.toml` 那边也要加一样的值（第 2.3 步）。
- `subDomainHost` 换成你自己的域名。

### 1.5 启动前的配置检查（先检查，再启动）

frp 0.71.0 的 `frps` / `frpc` 默认带 `--strict_config=true`（`cmd/frps/root.go`、
`cmd/frpc/sub/root.go`）：配置里出现任何结构体里没有的字段，解码阶段就报错
（`pkg/config/load.go`），进程打印错误后以退出码 1 退出。**未知字段不会被静默忽略**，
旧版 RUNBOOK 里"frp 的 TOML 解析对未知字段静默忽略"的说法是错的。`verify` 子命令
走的是同一套解析和校验（`cmd/frps/verify.go`、`cmd/frpc/sub/verify.go`），只检查配置，
不监听端口、也不连服务器：

```bash
cd /path/to/weekend0
./frps verify -c frps.toml
# 应该输出: frps: the configuration file frps.toml syntax is ok
./frpc verify -c frpc.toml
# 应该输出: frpc: the configuration file frpc.toml syntax is ok
# （这里用的是 linux 包里的 frpc，只为提前发现配置问题；OPNsense 上第 2.4 步会再检查一次）
```

前面可能还会多一行 `WARNING: ...`，那是校验器的提示，不是失败；看到别的报错就先修
配置，不要往下走。

`strict_config` 拦得住"未知字段"，拦不住"字段放错了表、但在新位置上恰好也合法"
的情况。最典型的是 `frpc.toml` 的 `metadatas.*`：它如果落到 `[[proxies]]` 下面，会变成
这条代理自己的 metadatas，`verify` 照样通过，但 Login 请求里的 `metas` 是空的（见
`frpc.toml` 开头的注释）。所以再用 Python 3.11+ 自带的 `tomllib` 把顶层结构打印出来，
人眼确认一遍（VPS 上的 `python3` 低于 3.11 就没有 `tomllib`，那就对照两份 `.toml` 开头的
注释逐行人眼检查）：

```bash
python3 -c 'import tomllib; c=tomllib.load(open("frpc.toml","rb")); print(sorted(c)); print(c["transport"]); print(sorted(c["proxies"][0]))'
# 应该是: ['log', 'metadatas', 'proxies', 'serverAddr', 'serverPort', 'transport']（加了 auth.token 的话还有 'auth'）
#         {'tls': {'enable': True}, 'heartbeatInterval': 10, 'heartbeatTimeout': 30}
#         ['localIP', 'localPort', 'name', 'subdomain', 'type']
python3 -c 'import tomllib; s=tomllib.load(open("frps.toml","rb")); print(sorted(s)); print(s["transport"]); print(s["httpPlugins"][0]["ops"])'
# 应该是: ['bindPort', 'httpPlugins', 'log', 'subDomainHost', 'transport', 'vhostHTTPSPort', 'webServer']（加了 auth.token 的话还有 'auth'）
#         {'heartbeatTimeout': 30}
#         ['Login', 'NewProxy', 'NewUserConn', 'Ping']
```

`transport` 里的两行心跳（frpc）和一行心跳超时（frps）是为验收项⑥加的，必须在顶层：
落到 `[[proxies]]` 或 `[webServer]` 下面会因为未知字段直接报错退出；但如果整行被删掉，
`verify` 照样通过，frpc 却根本不会发 `Ping`（`tcpMux` 默认开着时心跳默认关，见 `frpc.toml`
的注释），⑥会被误判成"拒绝 Ping 断不了线"。所以这里要确认它们真的在。

### 1.6 启动探针（先起探针，再起 frps，这样 frps 一启动就能连上）

先在 VPS 的 shell 里定义一个写模式文件的小函数（每个要切模式的终端里都定义一次）。
它先写临时文件再 `mv`，探针不会读到写了一半的内容；同时打印写入时刻，验收项⑥要拿它
算断线时延（格式跟 frps 日志的时间戳一致，用的是 VPS 本地时间）：

```bash
w0modes() {
  printf '%s\n' "$1" > /tmp/w0-modes.json.tmp && mv /tmp/w0-modes.json.tmp /tmp/w0-modes.json &&
    echo "$(date '+%F %T.%3N') 模式文件 <- $1"
}
w0modes '{}'      # 先建一个"不覆盖任何 op"的模式文件
```

模式文件放在 `/tmp`，不放在套件目录里，免得被误提交。然后启动探针：

```bash
cd /path/to/weekend0
PROBE_MODES_FILE=/tmp/w0-modes.json PROBE_PORT=9000 python3 probe.py
# 另开一个终端/tmux 窗口跑这个，留着看输出；同目录下会同时生成 probe.log
```

`probe.py` 的应答模式可以按 op 分别设（后面验收项③⑤⑥要用）。优先级从高到低：模式文件
里这个 op 的键 → `PROBE_MODE_<OP>` → `PROBE_MODE` → 默认 `allow`：

| 设置 | 作用 | 取值 |
|---|---|---|
| `PROBE_MODES_FILE` | 模式文件路径；**运行中改文件就能换模式，不用重启探针**。不设就没有这个功能 | 路径，本文用 `/tmp/w0-modes.json` |
| `PROBE_MODE` | 所有 op 的默认模式，不设就是 `allow` | `allow` \| `deny` \| `hang` \| `error500` |
| `PROBE_MODE_LOGIN` | 只覆盖 `op=Login` | 同上 |
| `PROBE_MODE_NEWPROXY` | 只覆盖 `op=NewProxy` | 同上 |
| `PROBE_MODE_NEWUSERCONN` | 只覆盖 `op=NewUserConn` | 同上 |
| `PROBE_MODE_PING` | 只覆盖 `op=Ping` | 同上 |
| `PROBE_HANG_SECONDS` | `hang` 模式睡多久，默认 30（只在启动时读） | 秒数 |
| `PROBE_PORT` / `PROBE_HOST` | 监听端口 / 地址，默认 `9000` / `127.0.0.1` | 跟 `frps.toml` 的 `httpPlugins.addr` 保持一致 |
| `PROBE_LOG_FILE` | 日志文件，默认当前目录下的 `probe.log` | 路径 |

**模式文件**是一个 JSON 对象，键是 op 名（`Login` / `NewProxy` / `NewUserConn` / `Ping`，大小写
要一致），值是模式，例如 `w0modes '{"Ping":"deny","NewUserConn":"allow"}'`；没写的 op 按环境
变量走，`w0modes '{}'` 就是全部恢复成环境变量（本文的启动命令没设任何模式环境变量，所以
就是全 `allow`）。探针每收到一个请求就重读一次文件，内容一变，从这个请求开始生效，并打印
`>>> 模式文件已重新加载：...`。内容写错（不是 JSON 对象、键拼错、模式值写错、空文件）、
文件读不了或被删掉：探针用一大块 `!!!` 报错，**忽略这次内容、沿用上一次合法的内容**，之后
每条请求记录里都带一行 `!!! 注意：模式文件当前无效……`，直到文件恢复合法。启动时文件存在
但内容不合法，探针直接拒绝启动。

op 取自 frps 请求的查询串 `?op=...`。探针启动时会把每个 op 最终用的模式和来源打印出来，
每条请求记录里也带着 `mode=... 来源=file|env|default（...）`。环境变量里的模式值写错（比如
`deney`）会直接拒绝启动——不会悄悄当成 `allow`，否则一个拼写错误就会被误读成"fail-open"。
每条记录都带着按 op 分开的累计计数（`累计 Login=1 NewProxy=1 NewUserConn=7 Ping=12` 这样）和
"距本 op 上一次请求过了几秒"，Ctrl+C 退出时也会打印一次总数。`Ping` 每 10 秒一条，完整 body
只在本次运行的第 1 次打印，之后只打一行摘要。

**不要靠重启探针来清零计数或换模式**：要数某个动作触发了几次，记下动作前后的累计计数相减。
重启探针只在 frpc 已经停掉的时候做（比如验收项③每组之间）。

注意：`frps.toml` 订阅了 `NewUserConn` 和 `Ping`，所以从现在开始：

- 每一条打到 8443 的浏览器连接都要先问探针。探针没起、或者 `NewUserConn` 不是 `allow`，
  浏览器那边就打不开页面（源码上是 fail-closed，见验收项⑤）。**验收项①～④期间保持
  `NewUserConn` 为 `allow`**。
- frpc 连上之后每 10 秒一次的 `Ping` 也要先问探针。探针没起、正在重启、或者 `Ping` 不是
  `allow`，按源码 frpc 约 10 秒内就会断开整条隧道（见验收项⑥）。**验收项①～⑤期间保持 `Ping` 为
  `allow`，探针不能停。**

### 1.7 启动 frps

再开一个终端/tmux 窗口：

```bash
cd /path/to/weekend0
./frps -c frps.toml
```

正常情况下你会在 frps 的日志里看到类似下面这几行（地址以你的配置为准），而且进程
没有报错退出：`plugin [nethub-probe] has been registered`、
`frps tcp listen on 0.0.0.0:7000`、`https service listen on 0.0.0.0:8443`、
`dashboard listen on 127.0.0.1:7500`、`frps started successfully`。
如果报错退出，先看是不是端口被占用；配置字段的问题第 1.5 步就应该已经暴露了——
strict_config 下拼错字段名会直接报错，不会等到运行时才行为诡异。

---

## 第 2 步：在 OPNsense 上临时手工跑 frpc（不装插件）

**这一步操作的是一台测试机，不是生产 OPNsense。** 全程手工，跑完必须清理，
不留任何常驻进程、开机启动项或配置文件。

### 2.1 SSH 进 OPNsense，确认 Web UI 本地端口

OPNsense 默认 Web UI 跑在 443（HTTPS），打包仓库那台专用测试机改过端口。Web UI 由
lighttpd 提供，用下面的命令看它实际监听的端口：

```sh
sockstat -4 -l | grep lighttpd
```

如果你的 OPNsense 把管理端口改成了别的（比如 8443、10443），记得同步改
`frpc.toml` 里 `localPort` 的值。

### 2.2 把 frpc 二进制和配置传上去

```sh
# 在你自己的机器上执行，换成真实的 OPNsense 测试机地址
scp frp_0.71.0_freebsd_amd64/frpc frpc.toml root@<opnsense测试机>:/tmp/
```

### 2.3 改 frpc.toml 里的占位值

- `serverAddr` 换成你 VPS 的真实公网 IP（或域名）。
- `subdomain` 保持 `weekend0-test`，或者换成任何你喜欢的、还没被占用的子域名。
- `localPort` 改成测试机实际的 GUI 端口（第 2.1 步查到的那个）。打包仓库那台专用测试机的
  GUI 不在 443。
- 如果你按第 1.4 步给 frps 加了 `auth.token`，这里也要填一样的值：去掉
  `frpc.toml` 里那行 `# auth.token = ...` 的注释。它必须留在原位（顶层，`[[proxies]]`
  之前），挪到 `[[proxies]]` 下面就会变成 `proxies[0].auth`，strict_config 下 frpc
  直接报错退出。
- 不要往 `[[proxies]]` 下面加任何顶层字段（`log.*`、`metadatas.*`、`transport.*`），
  原因见 `frpc.toml` 开头的注释。

### 2.4 启动前的配置检查

```sh
cd /tmp
chmod +x frpc
./frpc verify -c frpc.toml
# 应该输出: frpc: the configuration file frpc.toml syntax is ok
```

报错就先修配置（第 1.5 步的说明同样适用），不要往下走。

### 2.5 手工前台运行（不装插件、不用 rc.d，就是一个前台进程）

```sh
cd /tmp
./frpc -c frpc.toml
```

正常情况下日志会先显示 `login to server success, get run id [...]`，然后是这条代理
注册成功的信息 `[opnsense-webui] start proxy success`——方括号里是代理名
（`frpc.toml` 里 `[[proxies]]` 的 `name`），不是域名。同时探针那边应该开始每 10 秒左右收到
一条 `op=Ping`（`距本 op 上一次 10.0 秒` 上下）——这说明 `frpc.toml` 里的显式心跳生效了、
frps 每次心跳都在问插件。**这时候可以去做第 3 步的六项验收了**，先别关掉这个终端。

如果探针一直收不到 `Ping`：先用第 1.5 步的 `tomllib` 命令确认 `frpc.toml` 的 `transport` 里有
`heartbeatInterval` 和 `heartbeatTimeout`，再确认 `frps.toml` 的 `ops` 里有 `"Ping"`。

如果这台测试机同时装着 os-frp：顺手确认 os-frp 自己的 frpc 进程（如果它在跑）没有
受影响，两者用的是不同的二进制、不同的配置文件，也不抢同一个本地端口。记一笔进
`results-template.md`，算是 Weekend 2 共存测试的预览。

### 2.6 验证完之后务必清理

六项验收全部做完、结果也记录进 `results-template.md` 之后：

```sh
# 在 OPNsense 测试机上，Ctrl+C 停掉前台运行的 frpc，然后：
rm -f /tmp/frpc /tmp/frpc.toml
rm -rf /tmp/frp_0.71.0_freebsd_amd64*
```

确认没有残留任何 crontab、rc.conf 改动、开机脚本——手工跑这一步压根不该碰这些
地方，只是提醒你检查一遍。VPS 上 frps/probe.py 也可以在验收结束后 Ctrl+C 停掉。

---

## 第 3 步：六项验收

顺序按①→⑥做。除非某一项明确要求换模式，探针一律保持全 `allow`（模式文件是 `{}`，
不设任何 `PROBE_MODE*` 环境变量）。①～⑤期间 `Ping` 必须是 `allow`、探针不能停（见开头
那条提示）；换模式用 `w0modes`，每次切完看一眼探针打印的 `>>> 模式文件已重新加载` 和
下一条记录里的 `mode=... 来源=...` 是不是你想要的。

### 验收项 ①：外部网络能打开、能登录 OPNsense 登录页

**怎么做**：手机切到 4G/5G（关掉 WiFi，确保走的是运营商网络，不是家里/公司的
同一条出口线路，否则测不出"跨 NAT"的效果），浏览器打开
`https://weekend0-test.router.example.com:8443`（换成你自己配的子域名和域名）。

**观察什么**：
- 页面是否能加载出 OPNsense 的登录界面（用户名/密码框、OPNsense 的 logo 和
  样式）。
- 浏览器大概率会弹出证书不受信任的警告——**这是预期行为，不算失败**。
  原因：OPNsense 默认用的是自签证书，证书的 CN/SAN 对应的是设备自己的主机名，
  不是 `weekend0-test.router.example.com` 这个域名；而 frp 这边做的是纯 SNI
  转发——frps 只看 ClientHello 里的域名决定转发到哪台设备，
  完全不校验、也看不到证书内容，所以证书警告跟"穿透链路通不通"是两件独立的事。
  点击"继续访问/高级/接受风险"，只要后面能看到登录页就算这一步通过。
- 点击继续后，尝试用 OPNsense 的真实管理员账号密码登录，确认能进到 Dashboard，
  页面上的 JS/CSS 资源、AJAX 请求（比如仪表盘的实时图表）都正常，没有资源
  404、没有明显的内容被截断或改写的迹象。

- **OPNsense 自己的主机名检查（DESIGN §14 Q9，未实测）。** OPNsense 的 Web GUI 有 DNS 重绑定检查和
  HTTP_REFERER 检查（System → Settings → Administration）。经中继访问时，浏览器带的主机名是
  `weekend0-test.router.example.com`，不是设备自己的主机名，很可能看到一个写着"DNS Rebind"之类字样的
  错误页，或者登录后操作被拒。**这不是穿透失败。** 遇到时：
  1. 截图，原样记录看到的错误；
  2. 在测试机的 Administration 页面，把 `weekend0-test.router.example.com` 加进"Alternate Hostnames"，保存；
  3. 重新测一遍，并在结果里写清楚"需要加 Alternate Hostnames 才能用"。
  不要为了通过去关闭这两项检查；这个结果要交给 Kazuha 决定 Q9。

**判定标准（通过）**：登录页完整渲染、账号密码验证通过、进入后台看到的
Dashboard 功能正常，没有资源加载失败。证书警告不影响判定。若需要加 Alternate Hostnames
才能通过，也算通过，但必须在结果里注明。

**不通过意味着什么**：
- 如果页面完全打不开（连接超时/拒绝）：先看 frps 日志有没有收到 TLS
  ClientHello、8443 端口是不是真的被墙外可达（用验收项④的方法单独测一下端口
  连通性）、以及 `subDomainHost` 拼写、DNS 解析是否已经生效。
- 再看探针：`probe.py` 有没有在跑、`NewUserConn` 和 `Ping` 是不是 `allow`。frps 订阅了
  `NewUserConn`，探针不在或者拒绝时，frps 日志里会有
  `the user conn [...] was rejected`，浏览器这边表现为连接被直接断开；`Ping` 失败时 frpc
  日志里会有 `pong message contains error: ...` 并断开重连——这些都是探针造成的，不是穿透
  链路本身的问题。
- 如果页面打开了但样式全乱/JS 报错/内容被截断：这是比"打不开"更严重的信号
  ——意味着 SNI 透传可能没有生效，走成了某种会解析/改写 HTTP 内容的路径
  （比如误配成了 `type = "http"`），需要回去检查 `frpc.toml` 里 `type` 字段。

**下一步**：通过了才有必要做后面五项——如果连基本的登录页都打不开，产品的
地基就不成立，其它几项的结果都没有意义。

---

### 验收项 ②：拿到 Login/NewProxy 真实字段名，确认能否做归属校验

这是本次验证优先级最高的一项。

**背景（写进这份 RUNBOOK，方便你核对实测结果是否符合预期）**：

查过 fatedier/frp v0.71.0 tag 上的源码（`pkg/plugin/server/types.go`、
`server/service.go`、`server/control.go`）之后，关键结论是：

- `Login` 请求会把 frpc 发来的**原始** `msg.Login` 转成 JSON POST 给
  `httpPlugins`，其中包含 `metas`（对应 `frpc.toml` 里
  `metadatas.*`）、`client_id`、`hostname`、`run_id`（如果 frpc 自己带了的话，
  通常是空，由 frps 之后分配）等字段。**这次调用发生在 frps 给这个连接分配
  服务端 `run_id` 之前**（`server/service.go` 里先调用
  `pluginManager.Login`，返回不出错才继续走 `RegisterControl` 去生成
  `run_id`）。0.71.0 的 `LoginContent`（`pkg/plugin/server/types.go`）还在
  `msg.Login` 之外多带一个 `client_address`，值是 frps 看到的 frpc 控制连接对端
  地址（`server/service.go` 里取 `conn.RemoteAddr().String()`，`ip:port` 格式）。
- `NewProxy` 请求的 JSON body 结构是
  `{"user": {"user": ..., "metas": ..., "run_id": ...}, "proxy_name": ...,
  "proxy_type": ..., "custom_domains": [...], "subdomain": ..., ...}`。
  这里的 `user.metas` **不是**这次 `NewProxy` 消息自己带的 meta（那个是
  单独的 `metas` 字段，对应 frpc 里每个 `[[proxies]]` 自己的
  `metadatas.*`），而是 frps 在服务端从这个控制连接当前保存的
  `LoginMsg.Metas` 里现取出来塞进去的（`server/control.go`
  `loginUserInfo()`）。也就是说：**只要 Login 阶段验证通过、没有被插件改写，
  同一个设备后续每一次 NewProxy 请求，`user.metas` 里都会带着 Login 时那份
  设备身份信息，跟这次请求要注册的 `custom_domains`/`subdomain` 一起出现在
  同一个 JSON body 里**。这意味着归属校验可以在 `NewProxy` 这一步单次请求内
  完成（"签名有效 且 与数据库记录一致"两条都能就地核对），不需要控制面自己
  再维护一份"这个 run_id 对应哪个设备"的跨请求会话状态。

**怎么做**：
1. 确认 `probe.py` 处于 `PROBE_MODE=allow`（默认值）。
2. 在 OPNsense 测试机上重新跑一次 `./frpc -c frpc.toml`（哪怕它已经在跑，
   Ctrl+C 停掉再重新前台跑一次，确保触发一次全新的 Login + NewProxy）。
3. 回到 VPS 上看 `probe.log`（或者直接看 probe.py 的 stdout），应该能看到
   一条 `op=Login` 和一条 `op=NewProxy`。如果期间有浏览器连着 8443，中间还会夹着
   `op=NewUserConn` 的记录，那是验收项⑤要看的；每 10 秒一条的 `op=Ping` 是验收项⑥要看的，
   这里都先跳过。

**观察什么**：
- `op=Login` 那条记录里，`content` 下有没有 `metas` 字段，里面是不是能看到
  `frpc.toml` 里配的 `device_id: "weekend0-test-device"` 和
  `claim_placeholder: "REPLACE_WITH_SIGNED_DOMAIN_CLAIM"` 这两个键值原样出现；
  `content.client_address` 是不是测试机的出口地址。
- `op=NewProxy` 那条记录里：
  - 有没有 `custom_domains` 或者 `subdomain` 字段，值是不是
    `weekend0-test`（或者你实际配的子域名）。
  - `content.user.metas` 里能不能看到跟 Login 那条一样的
    `device_id`/`claim_placeholder`。
  - `content.user.run_id` 是不是一个非空字符串（这是 frps 服务端分配的，
    Login 那条记录里对应字段大概率是空，因为 frpc 没主动带 run_id）。

**判定标准（通过）**：上述字段全部按预期出现——尤其是 `NewProxy` 请求里
同时有"设备身份信息（`user.metas`）"和"它要注册的域名
（`custom_domains`/`subdomain`）"。这样控制面插件在 `NewProxy` 这一步就能做
到：① 校验 `user.metas` 里携带的签名声明本身有效（HMAC 验签），② 查数据库
确认这个设备的记录里，注册的域名字段确实等于这次请求的
`custom_domains[0]`/`subdomain`，③ 两条都过才放行（`{"reject": false,
"unchange": true}`），否则拒绝（`{"reject": true, "reject_reason": "..."}`）。

**不通过意味着什么**：
- 如果 `metas` 压根没有出现在 Login 请求里：**先排除表作用域问题**——用第 1.5 步的
  `tomllib` 命令确认 `metadatas` 在 `frpc.toml` 的顶层。如果它落在了 `[[proxies]]`
  下面，`verify` 不会报错，但这两个键值会出现在 NewProxy 的 `content.metas`（代理级）
  里，而不是 Login 的 `content.metas` / NewProxy 的 `content.user.metas`。排除这一点之后，
  才说明 `metadatas.*` 这个 frpc 配置字段名或者语义理解错了，需要回去核对
  `client.go` 里的字段名（不是本次验证的主要风险点，大概率是配置问题）。
- 如果 `user.metas` 没有出现在 NewProxy 请求里，或者是空的：这是**架构级
  的坏消息**——意味着归属校验没法在 NewProxy 这一步独立完成，必须退化成
  "在 Login 阶段做一次性校验 + 控制面插件自己维护一份 run_id → device_id
  的会话映射表，NewProxy 阶段查这份映射表"。这会让控制面插件从无状态变成
  有状态，多了一类新的故障模式（映射表和真实连接状态不一致、控制面重启后
  映射表丢失导致所有已连接设备的后续 NewProxy 被误判等），需要重新画一版
  安全模型图，并且要重新评估验收项③（fail-open/fail-closed）的严重性
  ——因为这时候控制面插件不仅要响应请求，还要维护状态，出问题的概率更高。

**下一步**：把实测到的完整 Login/NewProxy JSON 结构存一份（`probe.log`
本身就是证据），誊抄关键字段名进 `proto/` 目录，作为后续实现控制面插件时的
输入契约备注（哪些字段来自 frp 本身、哪些是 NetHub 自己往 `metas` 里塞的）。

---

### 验收项 ③：探针 deny / hang / error500 时，frps 对 Login 和新代理注册是拒绝还是放行

这条结果直接决定"控制面单点故障"在威胁模型里的严重等级，**不管测出来是
fail-open 还是 fail-closed，都要把结论写进风险清单**（不是只有"意外结果"
才需要记录）。

**为什么要按 op 分开测**：frpc 每次启动都是先 Login、Login 通过后才发 NewProxy。
如果只设一个全局 deny，被拒的其实是 Login，frpc 根本走不到 NewProxy 那一步，测出来的是
Login 的行为，不是 NewProxy 的。所以下面 NewProxy 的几组都在模式文件里写 `"Login":"allow"`
把 Login 放过去，单独拿 `"NewProxy"` 制造故障；Login 自己的行为另外单独测一组。全局 deny
还会顺带拒掉 `Ping`，让隧道在 10 秒内断开，结果更说不清，所以这里一律按 op 写。

**背景（源码依据，实测应该验证这个结论，而不是假设它一定对）**：

`pkg/plugin/server/manager.go` 里 `handleMutableContent`（`Manager.Login`、
`Manager.NewProxy`、`Manager.NewUserConn` 都是它的特化调用）的逻辑是：只要
`p.Handle(...)` 返回非 nil 的 `err`（HTTP 状态码非 200、连接失败、超时……任何非
"成功拿到一个合法 JSON 响应"的情况都算），就直接 `return nil, errors.New(...)`，
**完全不会走到"放行"分支**；探针返回 `"reject": true` 时同样返回错误。再往上一层，
`server/control.go` 的 `handleNewProxy`：

```go
retContent, err := ctl.sessionCtx.PluginManager.NewProxy(content)
if err == nil {
    inMsg = &retContent.NewProxy
    remoteAddr, err = ctl.RegisterProxy(inMsg)
}
```

`err != nil` 时压根不会调用 `ctl.RegisterProxy`——也就是说**从源码看，
0.71.0 版本对 NewProxy 的处理是 fail-closed：探针出错/超时/返回非 200，
这次代理注册会被拒绝，不会被放行**。Login 同理：`server/service.go` 里
`pluginManager.Login` 出错时不会调用 `RegisterControl`，frps 记一条
`register control error: ...`。

但源码分析不能替代实测——尤其是"hang"这种情况，因为
`pkg/plugin/server/http.go` 里发请求用的是没配置 `Timeout` 的
`http.Client{}`，而且传给它的 `context.Context` 来自
`context.Background()`，没有任何 deadline。这意味着**从 frps 自身的角度看，
它对一次插件调用的等待时间没有任何上限**——只要探针不回应，处理这次请求的那个
goroutine 就会一直被挂起，直到探针响应，或者底层 TCP 连接因为操作系统层面的原因
（比如连接被中间设备掐断）而报错。这不代表"整个 frps 进程卡死"（其他客户端的连接
不受影响），但对于**正在等待这次结果的这台设备**来说，效果是"这台设备这次连接
尝试彻底卡住，没有任何 frps 侧的超时兜底"。

还有三处源码细节，实测时顺便确认：

- frps 这一侧，同一条控制连接上的消息是**串行**处理的：`pkg/msg/handler.go` 的
  `readLoop` 直接调用 handler，而 `server/control.go` 注册 `NewProxy`、`Ping`、
  `CloseProxy` 时没有包 `AsyncHandler`。所以 NewProxy 卡住期间，这台设备后续的
  控制消息（包括 frpc 重发的 NewProxy，**以及每 10 秒一次的心跳 `Ping`**）预计都排在后面等。
- frpc 这一侧有自己的重试节奏（`client/proxy/proxy_wrapper.go`）：发出 NewProxy 后
  20 秒（`waitResponseTimeout`）没等到回应会重发一次，每 3 秒检查一次状态
  （`statusCheckInterval`）；被拒之后 30 秒（`startErrTimeout`）再试。所以 hang 时
  探针的 `NewProxy` 计数预计会涨到不止 1。Login 被拒时，frpc 默认
  `loginFailExit = true`，第一次登录失败就退出，不会重试。
- **本套件开着显式心跳（为验收项⑥），这会改变 NewProxy hang 的表现。** 上一条说的串行
  处理意味着 NewProxy 卡住期间 frps 不处理这台设备的 `Ping`，frpc 收不到 `Pong`、frps 也
  不刷新心跳时间。按源码，大约 30 秒后两边的心跳超时都会触发（frpc 的
  `transport.heartbeatTimeout = 30`、frps 的 `transport.heartbeatTimeout = 30`，日志都是
  `heartbeat timeout`），frpc 断开后重连。
  **重连不会马上成功。** 按 v0.71.0 源码（`server/service.go` 的 `RegisterControl`），同一个 `run_id`
  的新控制连接要先等旧控制连接的 worker 退出（`WaitForHandoff`）才会被激活；而旧连接的 `readLoop`
  正卡在那次没有超时的插件调用里。所以在探针那次 hang 返回之前，frpc 的重新 Login 收不到
  `LoginResp`（frpc 读 `LoginResp` 有 10 秒期限，见 `client/control_session.go`），会反复记
  `connect to server error: ... i/o timeout` 之类的错误重试。**这一轮的节奏由 `PROBE_HANG_SECONDS`
  决定，不只是 30 秒心跳超时。** 记下 hang 结束到 `start proxy success` 之间隔了多久。
  这正是生产上也开心跳时会出现的情况，照实记录。
- **`PROBE_HANG_SECONDS` 不要用默认的 30。** 它和两边的 `heartbeatTimeout = 30` 一样长，
  心跳超时和探针延迟放行谁先发生，是个不到一秒的竞态，结果不可复现。做 hang 这组时，
  趁 frpc 停着，用 `PROBE_HANG_SECONDS=120` 重启探针（见下面的步骤）。
- **hang 最后放行，不等于 fail-open。** 探针的 hang 模式睡完之后回的是 `allow`。如果会话撑过了
  这段时间，frpc 会接受这个迟到的 `NewProxyResp`（或者在 20 秒后重发时拿到 allow），代理就注册
  成功了。这是探针自己的延迟放行，说明的是"frps 不设超时、一直等插件"，**和 fail-closed 一致**。
  只有在探针**回应之前**代理就注册成功，才算 fail-open。想看不带心跳时的纯 NewProxy 重发节奏，需要同时
  注释掉 `frpc.toml` 的两行心跳和 `frps.toml` 的 `transport.heartbeatTimeout`（frps 要重启），
  这是可选项，测完记得改回来。

**怎么做（NewProxy 隔离：deny / error500 / hang）**：
每一组都是：在 OPNsense 测试机上 **先 Ctrl+C 停掉 frpc** → 在 VPS 上用 `w0modes` 切模式 →
重新跑 `./frpc -c frpc.toml` → 看 frpc、frps、probe 三边的输出。（frpc 停着时探针收不到请求，
`>>> 模式文件已重新加载` 要等 frpc 起来后的第一个请求才会打印；之后每条记录的
`mode=... 来源=file（...）` 能确认这一组的模式。）

```bash
# deny
w0modes '{"Login":"allow","NewProxy":"deny"}'
# error500
w0modes '{"Login":"allow","NewProxy":"error500"}'
# hang（先按下面的说明用 PROBE_HANG_SECONDS=120 重启探针，不要用默认的 30）
w0modes '{"Login":"allow","NewProxy":"hang"}'
```

`NewUserConn` 和 `Ping` 这几组里都不写，跟着环境变量（默认 `allow`）。

hang 这组要睡得比心跳超时长很多（上面说过，30 秒会撞上竞态），用 120 秒，这样也能顺带验证
"frps 真的没有超时上限"。`PROBE_HANG_SECONDS` 只在
探针启动时读，所以要重启探针——**趁 frpc 停着的时候重启**才安全（没有 frpc 在发 `Ping`）：
Ctrl+C 停掉探针，`PROBE_MODES_FILE=/tmp/w0-modes.json PROBE_HANG_SECONDS=120 python3 probe.py`
重新起来，再起 frpc。③做完之后同样趁 frpc 停着，把探针按第 1.6 步的命令重启回默认值。

hang 这组额外做两件事：
1. **用 `time ./frpc -c frpc.toml`** 或者自己掐表，记录从启动到 frpc 日志报错（或者
   代理最终注册成功）之间过了多久，以及探针里 `NewProxy` 的计数涨到了几。
2. 同时观察 frps 进程本身在 hang 期间是不是还能正常处理别的请求——在 VPS 上用
   `curl -s -u '<webServer.user>:<webServer.password>' http://127.0.0.1:7500/api/serverinfo`
   （或者 SSH 隧道过去开 dashboard）看 frps 是否仍正常响应；如果手头有第二台设备，
   在 hang 期间让它连一次，间接确认"卡住的只是这台设备的这次注册，不是整个
   frps 进程"。

**怎么做（Login 单独测：deny / error500）**：

```bash
w0modes '{"Login":"deny"}'
w0modes '{"Login":"error500"}'
```

同样每组都先停 frpc、切模式、再起 frpc，记录 frpc 是立刻退出还是重试、frps 日志里出现了
什么。时间够的话也可以补一组 `w0modes '{"Login":"hang"}'`，记录 frpc 在 Login 卡住时等了多久
（Login 卡住时还没有控制连接，心跳不参与）。

③全部做完：先停 frpc，`w0modes '{}'` 恢复全 `allow`，再起 frpc，确认 `start proxy success`
和探针里每 10 秒一条的 `Ping` 都回来了，再去做④。

**观察什么**：
- NewProxy `deny`/`error500`：frpc 日志里应该是 `[opnsense-webui] start error: ...`
  （按源码，frps 默认 `detailedErrorsToClient = true`，错误原因会带回给 frpc），frps
  日志里应该是 `new proxy [opnsense-webui] type [https] error: ...`。此时
  `frpc` 的登录本身是成功的（有 `login to server success`），只是代理没注册上；
  浏览器/curl 打 `https://weekend0-test.router.example.com:8443` 应该连不通（frps 上
  没有对应的 vhost 路由）。
- NewProxy `hang`：frpc 是"一直卡着不报错也不成功"，还是等了某个固定时间之后
  自己超时报错或者重发——这个"frpc 自己等多久"的时间是 frpc 侧的行为，跟 frps 有没有
  给插件调用设超时是两件事，实测记录下来，两个数字都有参考价值。探针里 `NewProxy`
  的计数和每次请求的时间戳能直接看出 frpc 的重发节奏。因为开着心跳，预计还会看到
  frpc / frps 两边约 30 秒一次的 `heartbeat timeout` 和随后的重连（见上面第三处源码细节），
  把它和 NewProxy 自己的 20 秒重发区分开记录。
- Login `deny`/`error500`：frpc 日志里预计是 `connect to server error: ...`，随后
  `login to the server failed: ... With loginFailExit enabled, no additional retries
  will be attempted` 并退出；frps 日志里预计是 `register control error: ...`；探针里
  只有 `Login` 计数，没有 `NewProxy`。

**判定标准（这里的"判定标准"更多是"实测是否符合源码分析"，而不是简单的
通过/不通过）**：
- 如果 NewProxy 的 `deny`/`error500`/`hang`（最终，即便等了很久）都表现为"这次
  NewProxy 被拒绝、代理没有注册成功"，Login 的 `deny`/`error500` 都表现为"登录被拒"
  ——跟源码分析一致，确认 0.71.0 是 fail-closed。
- hang 组里，代理在探针**睡完、回了 allow 之后**才注册成功，同样算跟源码一致（fail-closed，
  只是 frps 没有超时、一直等插件），不是 fail-open。
- 如果观察到任何一种情况下代理**居然注册成功了**（域名能访问到 OPNsense）——deny / error500
  组里任何时候注册成功，或者 hang 组里在探针回应**之前**就注册成功——或者
  Login 被拒了 frpc 却照样登录成功——跟源码分析不一致，这是本次验证里最值得警惕的
  一类结果，必须优先复核（探针每条记录里的 `mode=... 来源=...` 是不是你以为的那样、
  有没有 `!!! 注意：模式文件当前无效` 的提醒、是不是用了缓存的旧连接等），排除测试方法
  问题后，这个发现本身就要作为高优先级风险单独上报。

**不通过（也就是"确认是 fail-closed 但 hang 没有超时上限"）意味着什么**：
这条结论本身就是风险，不是"测完确认没问题"就能划掉的事——它意味着：
**归属校验控制面插件如果挂了（比如查 Postgres 卡住、HMAC 校验逻辑死循环、
进程被 OOM kill 但端口还占着没释放导致连接被 accept 但不处理……），所有
新建/重连的设备都会卡在 Login 或 NewProxy 这一步，且没有任何 frps 侧的超时把它们
解放出来**。只订阅 Login / NewProxy 的话，已经成功建立的隧道（代理已经注册过、
不需要重新走 NewProxy）理论上不受影响，但任何需要重新走一遍 Login+NewProxy 的场景
（frpc 重启、frps 重启、网络抖动导致重连）都会被卡住。如果以后启用 `NewUserConn` 门控
（Q7），这条风险还会扩大到"已经在线的设备也打不开 GUI"，见验收项⑤。**如果采用⑥的
`Ping` 断线机制，风险再扩大一级**：控制面一停或一卡，已经在线的隧道也会在约一个心跳
间隔（或一个心跳超时）内被切断，见验收项⑥的 6.6。

**下一步**：不管测出来是不是 fail-closed，都要在 `results-template.md`
的风险清单里写清楚这条结论，并且要求控制面插件实现时**自己**加一层超时
兜底（比如插件内部对 Postgres 查询设置几百毫秒的超时，超时就明确返回
拒绝，而不是让 HTTP 请求本身挂起）——不能指望 frps 会替你做这件事，
从源码看它不会。

---

### 验收项 ④：受限网络下 8443 的可达性与稳定性（对照同一台 VPS 上的 443）

只测 8443、拿一个绝对阈值去比，分不清"8443 这个端口不行"和"这条网络本来就差"。
所以在同一台 VPS 上临时起一个 443 的 TLS 基线监听，**在同一个循环里交替**采样 443 和
8443，两者只差端口号，比的是相对差距——这就是 DESIGN Q2 的决策规则要的数据。

**准备 443 基线（在 VPS 上，只在④期间存在）**：

1. 确认 VPS 的 443 没被别的服务占用，并按第 1.2 步临时放行 TCP 443。
2. 生成一张一次性的自签证书（放在套件目录之外的临时目录里，测完就删）：

   ```bash
   mkdir -p /tmp/w0-baseline && cd /tmp/w0-baseline
   openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
     -subj "/CN=baseline.router.example.com" \
     -keyout baseline-key.pem -out baseline-cert.pem
   ```

3. 另开一个终端/tmux 窗口，前台起基线监听（443 是特权端口，所以要 `sudo`）：

   ```bash
   cd /tmp/w0-baseline
   sudo openssl s_server -accept 443 -www -cert baseline-cert.pem -key baseline-key.pem
   ```

   `-www` 会对每个 `GET /` 回一个简单的 HTML 状态页，curl 能拿到 HTTP 200。它不看
   SNI，所以直接用 `weekend0-test.router.example.com:443` 去连就行（泛解析指向的是
   同一台 VPS）。

**怎么做**：分别在以下几类网络环境下采样（不只是打开网页看一眼，要能采出
"成功率"和"延迟"这两个数字）：
- 至少两家不同运营商的 4G/5G 移动网络（比如中国移动 + 中国联通/电信，或者
  你实际能拿到的任意两家）。手机上没有 curl 的话，可以让手机开热点、笔记本连上去跑，
  这样走的仍然是运营商的移动网络。
- 至少一个公司/校园网络（这类网络经常有更激进的出站过滤策略）。
- 如果条件允许，境外网络也测一下（用来判断问题是不是跟特定地区的网络策略
  有关）。
- 家用宽带作为对照组。

每个网络环境下，用下面的方式采样（不要只测一次，网络抖动是常态，至少连续
测 20 轮，每轮 443 和 8443 各一次，间隔几秒）：

```bash
for i in $(seq 1 20); do
  for port in 443 8443; do
    curl -o /dev/null -s -k --connect-timeout 5 --max-time 10 \
      -w "第${i}轮 port=${port} http=%{http_code} 连接耗时=%{time_connect}s TLS握手耗时=%{time_appconnect}s 总耗时=%{time_total}s\n" \
      "https://weekend0-test.router.example.com:${port}/"
  done
  sleep 2
done
```

（`-k` 是因为两边都是自签证书，这里只关心连通性，不关心证书校验结果；
`time_connect`/`time_appconnect` 分别是 TCP 三次握手耗时和 TLS 握手完成
耗时，两个都记录下来方便区分"连不上"和"连上了但握手慢/失败"。`http=000` 且
`连接耗时=0.000000s` 的那一次记为 TCP 连接失败。）

注意两边的 TLS 握手耗时不能直接比：443 的 TLS 在 VPS 上的 `s_server` 结束，8443 的 TLS
要穿过隧道一直到 OPNsense 才结束，天然多一段路。**主要比 TCP 连接成功率**，TLS 握手
耗时各自看分布即可。另外，按源码 8443 的每一条连接都会触发一次 `NewUserConn`，探针
日志会随之变长，这是正常的（探针保持全 `allow`，采样期间不要停探针，否则 `Ping` 失败会让
隧道断开，8443 的失败就不是网络的锅了）。

**观察什么**：
- 每个网络环境下，443 和 8443 各自 20 次里有几次在 `--connect-timeout 5` 内完成了
  TCP 连接（记为连接成功率），两者差多少个百分点。
- 连接成功的那些里，TLS 握手（`time_appconnect`）是不是也顺利完成、耗时
  分布大概在什么范围（正常网络下几十到几百毫秒；如果动辄几秒甚至超时，
  说明这条网络路径对这个端口不友好）。
- 是不是能观察到"同一个网络环境下，前几次失败、后面变稳定"或者反过来
  "一开始正常、几分钟后开始失败"这种非均匀模式——这种模式往往意味着运营商
  有基于流量特征的限速/QoS 策略，而不是单纯的端口封锁。

**Optional Windows sampler and CSV validation.**
[`sample-network.ps1`](sample-network.ps1) runs the same alternating 20-round
comparison with a fresh IPv4 curl process for each request. Run it only while
the relay's test listeners and all-allow probe are ready:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\weekend0\sample-network.ps1 -TestHostname weekend0-test.router.example.com -NetworkLabel A
```

Evidence defaults to `nethub-w0-results` under the user's home directory;
repository output paths are rejected. The raw CSV retains network addresses.
Share only the companion `*.sanitized.csv`, which excludes both addresses.
Labels A/B/C are enough; retain which distinct external networks they represent
in the private test record.

On macOS, use the POSIX sampler with the built-in curl, awk, and date tools;
no Python installation is needed to collect the sample:

```sh
sh weekend0/sample-network.sh weekend0-test.router.example.com A
```

It writes the same raw and sanitized CSV formats under
`$HOME/nethub-w0-results` by default. Keep the raw file private. Run one network
at a time while its relay test window is open; use B/C for subsequent networks.

```console
python weekend0/network_summary.py path/to/A.sanitized.csv
```

The validator requires exactly 40 rows in round/port order, consistent TCP
flags and finite timings. It reports per-port TCP counts, separate TLS
completion statistics, early/late failures, and the unchanged Q2 rule below.
A TCP connection followed by a TLS failure remains a TCP success. A valid CSV
does not prove external-network provenance or that relay listeners stayed
available; correlate it with the test window before accepting experiment ④.

**判定标准（DESIGN Q2 的规则，这是主判据）**：只有满足下面任意一条，才启动
"vhost-https 复用 443"这项工作，否则维持 8443：
- 任意一个网络环境下，**8443 的连接成功率比同一网络下 443 的低 20 个百分点以上**
  （20 次采样里就是少 4 次以上）；
- 任意一个网络环境下，**8443 一次都没连上**（0/20），不论同一网络下 443 的结果如何。

套件照 DESIGN Q2 原文执行，不加例外。如果某个网络下 443 也是 0/20，照样记为触发，同时在
`results-template.md` 里另外注明"443 也是 0/20"：这通常说明这条网络路径整体不通，或者采样本身
有问题（比如 `s_server` 没在监听、防火墙 443 没放行），读结果的人需要自己复核这个样本该不该作数。
如果结论是这种情况应当豁免，那是对 Q2 措辞的修改，应当回到 `docs/DESIGN.md` 去改，而不是在套件里
悄悄改规则。

**次要参考（绝对值，不作为决策依据）**：两个以上不同运营商的移动网络下，8443 的 TCP
连接成功率都在 18/20（90%）以上、TLS 握手耗时中位数在 1 秒以内，可以认为 8443 在
移动网络下大体可用。不管结果如何，都在 `results-template.md` 里按网络逐条记录
具体数字和现象。

**不通过意味着什么**：如果某类受限网络下 8443 连通性显著更差，意味着
NetHub 在那类网络下的用户体验会打折扣。复用到 443 是一个可选的缓解方向，
但要注意：按 DESIGN 的规划，443 要留给 Caddy 服务控制台和设备 enroll API，
frp 的 vhost-https 和它复用同一个端口需要第二个公网 IP，或者一层额外的 SNI 分流
（DESIGN Q2），这是本次验证范围之外的问题，先如实记录数据，复用方案留到看到实测
数据之后再决定。

**做完④之后马上清理基线**：Ctrl+C 停掉 `openssl s_server`，删掉证书和私钥
（`rm -rf /tmp/w0-baseline`），关掉防火墙上临时放行的 443。如果你图方便把证书生成在了
套件目录里，仓库的 `.gitignore` 虽然忽略 `*.pem`，也一样要删掉。

---

### 验收项 ⑤：Q7 数据——`NewUserConn` 对 https 代理是否触发、能不能挡住连接

**为什么要测**：SNI 透传之下，`https://weekend0-test.router.example.com:8443` 对任何
知道或猜到这个域名的人都直接给出 OPNsense 登录页，控制台的登录和 SSO 不挡在它前面
（DESIGN Q7）。候选缓解是：frps 每接受一条用户连接时先问一次插件（`NewUserConn`），
控制面只放行"最近有已登录的控制台用户为这台设备点过『打开』"的来源 IP。这条路
能不能走，取决于这一项的实测。**Weekend 0 只收集数据，不做任何真正的门控判断**；
门控要不要做由 Q7 决定。

**背景（2026-10-16 对照 fatedier/frp v0.71.0 tag 源码核对过的部分）**：

- `NewUserConn` 是合法的 httpPlugins op：`pkg/plugin/server/plugin.go` 定义了
  `OpNewUserConn = "NewUserConn"`，`pkg/config/v1/validation/validation.go` 的
  `SupportedHTTPPluginOps` 里有它，所以 `frps.toml` 的 `ops` 里写它能通过
  `./frps verify`；`pkg/plugin/server/manager.go` 的 `Register()` 会把订阅了它的插件
  放进 `newUserConnPlugins`。
- 请求体结构（`pkg/plugin/server/types.go` 的 `NewUserConnContent`）只有四个字段：
  `user`（`{"user", "metas", "run_id"}`）、`proxy_name`、`proxy_type`、`remote_addr`。
  `user` 由 frps 在代理注册时从这条控制连接的 Login 消息里取（`server/control.go`
  `RegisterProxy` 里构造 `plugin.UserInfo`），所以 `user.metas` 就是 Login 时的
  `metadatas.*`（本套件里的 `device_id` 等）——门控可以直接按设备身份判断，不需要
  另外维护 run_id 映射。请求体里**没有** SNI 域名、HTTP 路径之类的信息。
- 调用点在 `server/proxy/proxy.go` 的 `handleUserTCPConnection`：
  `startCommonTCPListenersHandler` 对每个 listener 起一个 accept 循环，每 accept 到
  一条连接就 `go pxy.handleUserTCPConnection(c)`，后者在向 frpc 要工作连接**之前**先调
  `rc.PluginManager.NewUserConn(content)`。`proxy_name` 是 frps 侧的代理名（frpc 没设
  `user` 时就是 `opnsense-webui`），`proxy_type` 取的是代理配置里的 `type`，
  `remote_addr` 取的是 `userConn.RemoteAddr().String()`。
- https 代理走的就是这条路径：`server/proxy/https.go` 的 `HTTPSProxy.Run()` 用
  `VhostHTTPSMuxer.Listen` 为每个域名建一个 listener，放进 `pxy.listeners`，然后调用
  `startCommonTCPListenersHandler()`。vhost 复用器（`pkg/util/vhost/vhost.go`、
  `https.go`）先读 ClientHello 取 SNI、找到对应代理之后，才把连接交给这个 listener；
  SNI 对不上任何代理的连接在复用器那一层就被关掉了，不会触发 `NewUserConn`。
- `remote_addr` 的来源：交给 listener 的连接是 golib `SharedConn`（为了窥探
  ClientHello）再包一层 `ContextConn`，两者都直接内嵌 `net.Conn`、没有重写
  `RemoteAddr()`，所以它是 frps 在 8443 上 accept 到的那条 TCP 连接的对端地址，格式是
  `ip:port`（IPv6 是 `[addr]:port`），门控用的时候要去掉端口。
- 拒绝的效果：`handleMutableContent` 返回错误（探针拒绝、非 200、连不上、出错都算）时，
  `handleUserTCPConnection` 记一条 `the user conn [<remote_addr>] was rejected, err:...`
  然后直接返回，`defer userConn.Close()` 把浏览器那条 TCP 连接关掉，**不会**去向 frpc
  要工作连接。所以从源码看 `NewUserConn` 也是 fail-closed，而且插件调用出错时那条
  `send NewUserConn request to plugin [...] error` 日志是 Info 级别，不是 Warn
  （`manager.go` 里刻意保留的）。hang 时同样没有超时，只卡住那一条连接（每条连接
  一个 goroutine）。
- 粒度是**每条 TCP 连接一次**，不是每个 HTTP 请求一次：钩子只在连接建立后、开始双向
  转发之前调用一次。同一条 keep-alive（或 HTTP/2）连接上后续的请求不会再触发。

**源码看不出来、必须实测的**：
1. 钩子在真实的 https vhost 代理上确实触发（探针收到 `op=NewUserConn`、
   `proxy_type=https`、`proxy_name=opnsense-webui`）。
2. `remote_addr` 等于手机当前的公网出口 IP（取决于 VPS 前面有没有云厂商的负载均衡
   之类改写源地址的东西）。
3. 打开一次 OPNsense 登录页、登录进 Dashboard 分别会产生几条连接、触发几次钩子。
4. 拒绝时浏览器确实拿不到页面，同时隧道本身（frpc 的登录和代理注册）不受影响。
5. 已经打开的页面在切换成拒绝之后还能不能继续用。

**怎么做**：

整项都**不要重启探针**：frps 订阅了 `Ping`，重启探针的那一两秒里到达的心跳会失败，按源码
frpc 随即断开整条隧道，标签页 A 会因为这个断开而不是因为 `NewUserConn` 拒绝而失效，结果就
混了。换模式全部用 `w0modes`；`Ping` 不写进模式文件，保持 `allow`。

1. **计数基线（allow）**：
   - 确认模式文件是 `{}`（`w0modes '{}'`），全 `allow`。**不要为了清零重启探针**：记下现在
     `NewUserConn` 的累计计数（看探针最近一条记录里的 `累计 ... NewUserConn=N`；还没出现过
     就是 0），后面的"触发了几次"都用前后计数相减。
   - 手机切 4G/5G（关 WiFi），先用手机浏览器打开任意一个显示本机公网 IP 的网站，记下
     IP。注意 IPv4/IPv6：VPS 只有 A 记录的话，手机连 8443 走的是 IPv4，要跟 IP 网站显示的
     IPv4 地址比。
   - 手机浏览器新开一个**无痕/隐私窗口**（避免复用之前的连接），打开
     `https://weekend0-test.router.example.com:8443`，等登录页完全加载完。记下探针里
     `NewUserConn` 的累计计数（跟上面的基线相减），以及每条 `NewUserConn 摘要` 行的
     `remote_addr`、`proxy_type`、`proxy_name`、`user.metas.device_id`。
   - 登录，进到 Dashboard，等实时图表刷新一两轮，再记一次计数。
2. **拒绝新连接（deny）**：
   - 在手机上**保留**一个已经登录、停在 Dashboard 的标签页（标签页 A）。
   - 在 VPS 上 `w0modes '{"NewUserConn":"deny"}'`（Login / NewProxy / Ping 都不写，保持
     `allow`；frpc 不用动）。下一条 `op=NewUserConn` 记录应该是 `mode=deny 来源=file（...）`。
   - 立刻在标签页 A 里点几个菜单、等 Dashboard 刷新：页面还能不能继续用？
   - 再开一个新的无痕窗口打开同一个地址：应该打不开（连接被直接断开）。
   - 同时确认隧道还在：frpc 终端里没有断线重连的日志；探针里 `Ping` 仍然每 10 秒一条、
     `mode=allow`；frps 日志里出现 `the user conn [...] was rejected`；在 VPS 上
     `curl -s -u '<webServer.user>:<webServer.password>' http://127.0.0.1:7500/api/proxy/https`
     里 `opnsense-webui` 的 `status` 仍是 `online`。（这也是 DESIGN §10 第 6 项里
     "`NewUserConn` deny 时控制连接是否保持"的答案，⑥直接引用这里的结果。）
3. （可选）**出错时的行为**：`w0modes '{"NewUserConn":"error500"}'`，再开一个无痕窗口试一次，
   确认跟 deny 一样打不开。这个结果的含义是：一旦启用门控，控制面出错就等于所有设备的
   GUI 都打不开。
4. 测完 `w0modes '{}'` 改回全 `allow`。

**观察什么 / 判定**：
- 钩子触发了，且 `proxy_type` 是 `https`：Q7 的门控在技术上有挂载点。没触发：门控这条
  路走不通，Q7 只能靠文档提示 + OPNsense 自己的 TOTP 2FA。
- `remote_addr` 的 IP 部分等于手机的公网 IP：门控能按来源 IP 判断。不等（比如是某个
  内网地址或负载均衡地址）：要先弄清 VPS 前面是什么在改写源地址，门控在这种部署下
  不可用。
- 一次登录页加载、一次登录 + Dashboard 各触发了几次：决定门控的查询频率和日志量。
- deny 时新窗口打不开、隧道仍在线：拒绝确实能挡住新连接，而且不伤隧道。
- 标签页 A 还能用多久：源码上已经建立的连接不受影响，但浏览器和 OPNsense 的
  lighttpd 都会关闭空闲连接，之后的新连接就会被拦。如实记录"还能用 / 很快就不能用了 /
  过了大约多久不能用"。这决定 IP 白名单的时间窗口过期之后用户体验是什么样。

---

### 验收项 ⑥：撤销/断线机制实测（拒绝 `Ping` + 显式心跳）

**为什么要测**：DESIGN §5 里 authz 每 15 秒轮询 frps admin API，只能**发现**被撤销或被盗的设备，
断不了它——对照 v0.71.0 源码，admin API 没有任何断开在线客户端或代理的接口。不另找机制，
被撤销的设备会一直在线，直到它自己因为别的原因重连。DESIGN §5 列的候选机制全部未经实测；
这一项验证主机制（对已撤销设备的 `Ping` 返回拒绝，配合 frpc 显式心跳），确认跟它一起生效的
补充（`NewUserConn` 拒绝，⑤已测"拒绝不伤隧道"），并记录主机制的代价。候选 3（重启 frps）
只作人工兜底，这里不测。

**背景（2026-10-16 对照 fatedier/frp v0.71.0 tag 源码核对过的部分）**：

(a) **frps 每次心跳都问一次插件，拒绝或出错时回一个带错误的 `Pong`**：

- `server/control.go` 的 `registerMsgHandlers` 把 `msg.Ping` 交给 `handlePing`（没有包
  `AsyncHandler`，跟 NewProxy 一样在 readLoop 里串行处理）。`handlePing` 对**每一个** Ping 都
  构造 `plugin.PingContent{User: ctl.loginUserInfo(), Ping: *inMsg}` 调 `PluginManager.Ping`，
  没有缓存、没有跳过。
- 请求体：`content.user` 是 `{"user", "metas", "run_id"}`（`loginUserInfo()`；`metas` 就是 Login
  时的 `metadatas.*`，`run_id` 是 frps 分配的），所以 authz 能直接按设备身份判断是否已撤销。
  `msg.Ping` 自己只有 `privilege_key`、`timestamp` 两个字段（`pkg/msg/msg.go`，都是
  `omitempty`），只有 `auth.additionalScopes` 里有 `HeartBeats` 时 frpc 才会填
  （`pkg/auth/token.go` 的 `SetPing`）。本套件没配，所以预计 `content` 里只有 `user`。
- `pkg/plugin/server/manager.go` 的 `Manager.Ping` 同样走 `handleMutableContent`：探针拒绝、
  非 200、连不上、出错都返回错误（fail-closed）。Ping 插件出错的日志是 Warn 级别的
  `send Ping request to plugin [nethub-probe] error: ...`。
- 出错时 `handlePing` 记 `received invalid ping: <原因>`，回 `msg.Pong{Error: ...}`
  （`detailedErrorsToClient` 默认 true，所以 `Error` 就是原因本身：拒绝时是探针的
  `reject_reason`，插件调用失败时是 `send Ping request to plugin error`），然后直接返回，
  **不刷新 `lastPing`**；只有成功时才刷新 `lastPing` 并回空 `Pong`。frps 在这里自己不断开连接。
- frps 侧的兜底是同一文件里的 `heartbeatWorker`：`transport.heartbeatTimeout > 0` 时每秒查一次，
  距上一次**成功的** Ping 超过这个秒数就记 `heartbeat timeout` 并关掉这个控制连接。因为被拒的
  Ping 不刷新 `lastPing`，即使 frpc 不理会带错误的 Pong，frps 也会在 `heartbeatTimeout`（本套件
  30 秒）内断开它的控制连接。

(b) **frpc 收到带错误的 `Pong` 就关掉整个会话，然后重连、重新 Login**：

- `client/control.go` 的 `handlePong`：`Error` 非空就记 Error 级别的
  `pong message contains error: <原因>`，调 `closeSession()`——关闭控制连接和 `Connector`
  （tcpMux 下就是整个 yamux 会话，见 (d)）。随后 dispatcher 退出，`worker()` 关掉所有代理。
- 重连：`client/service.go` 的 `keepControllerWorking` 等到这个控制结束，就调
  `loopLoginUntilSuccess(20*time.Second, false)`：新建一条 TCP 连接和新的 yamux 会话
  （`client/control_session.go` 的 `Dial`），重新发 Login（带上之前那个 run id，`buildLoginMsg`），
  Login 成功后重新注册代理。
- Login 被拒时：日志 `connect to server error: <原因>`，**不会退出**——`loginFailExit` 只管进程
  启动时的第一次登录（`Run()` 里是 `loopLoginUntilSuccess(10*time.Second, LoginFailExit)`，之后的
  重连固定传 `false`）。重试间隔按 `pkg/util/wait/backoff.go`：约 2 秒起翻倍（最多 10% 抖动），
  封顶 20 秒，一直重试下去。所以被撤销的设备会以最多约 20 秒一次的频率持续来敲 Login，authz
  要能便宜地拒掉它。
- 只拒绝 Ping、Login 仍放行时：重连会成功、代理会重新注册；但新会话一建立 frpc 就立刻发第一次
  Ping（`heartbeatWorker` 用 `wait.BackoffUntil`，第一次调用不等待，之后固定每
  `heartbeatInterval` 一次），随即又被断开。预计是"反复连上、马上又断"：外层
  `keepControllerWorking` 的退避一开始有几次约 0.2 秒的快速重试，之后逐步拉长，封顶 20 秒。第一次
  Ping 和 NewProxy 几乎同时发出，所以每一轮里很可能有一个很短的窗口，代理是注册着的。所以断线
  必须同时拒绝 Login，单靠拒绝 Ping 挡不住设备回来。
- frpc 自己的心跳超时：`heartbeatInterval > 0` 且 `heartbeatTimeout > 0` 时，距上一次收到 Pong
  超过 `heartbeatTimeout` 就记 `heartbeat timeout` 并 `closeSession()`。

(c) **心跳默认是关的，必须显式打开**：

- `pkg/config/v1/client.go` 的 `ClientTransportConfig.Complete()`：`tcpMux` 默认 true；tcpMux 为
  true 时 `heartbeatInterval`、`heartbeatTimeout` 默认都是 -1（为 false 时才是 30 / 90）。frpc 的
  `heartbeatWorker` 只在 `heartbeatInterval > 0` 时发 Ping，所以**默认配置下 frpc 根本不发 Ping**，
  frps 的 Ping 钩子永远不会被调用。
- `pkg/config/v1/server.go` 的 `ServerTransportConfig.Complete()`：tcpMux 为 true 时 frps 的
  `heartbeatTimeout` 默认也是 -1，frps 的 `heartbeatWorker` 直接返回、什么都不查。
- 所以本套件显式写了 frpc 的 `transport.heartbeatInterval = 10`、`transport.heartbeatTimeout = 30`
  和 frps 的 `transport.heartbeatTimeout = 30`。json tag 已对照 `ClientTransportConfig` /
  `ServerTransportConfig` 核对；`Complete()` 用 `EmptyOr` 只替换零值，显式值原样保留；
  `pkg/config/v1/validation/client.go` 要求两者都大于 0 时 timeout 不小于 interval。
  `transport.tcpMux` 本身不用改。

(d) **tcpMux 下工作连接和控制连接是同一个 yamux 会话上的流**：

- `client/connector.go`：tcpMux 为 true 时 `Open()` 建一条到 frps 的 TCP（+TLS）连接，在上面起
  一个 yamux 客户端会话（`github.com/hashicorp/yamux`，`go.mod` 里 replace 成
  `github.com/fatedier/yamux`）；之后每次 `Connect()` 都是 `OpenStream()`。控制连接
  （`Dial` 里的 `connector.Connect()`）和每一条工作连接（`client/control.go` 的
  `handleReqWorkConn` → `Connector.Connect()`）都是**这个会话上的流**。frps 这边
  `server/service.go` 的 `HandleListener` 用 `fmux.Server` 接这个会话，每条流交给
  `handleConnection`。
- frpc 的 `closeSession()` 调 `Connector.Close()` → `muxSession.Close()`；fatedier/yamux 的
  `Session.Close()` 关掉底层 TCP 连接，并对每一条流 `forceClose()`。所以按源码，frpc 因为带错误的
  Pong（或心跳超时）断开时，**已经在转发的浏览器连接也会随之断开**。
- frps 侧断开（`heartbeat timeout`）只关控制那一条流；之后关代理时
  `server/proxy/proxy.go` 的 `BaseProxy.Close()` 只关 listener（`HTTPSProxy.Close()` 也只是调它），
  不碰已建立的用户连接，那些连接要等各自的工作流结束。原版 frpc 看到控制流被关会自己
  `closeSession()`，整个会话一起断；一个被改过、不肯关会话的 frpc，按源码已经打开的流可能在
  frps 断开控制连接之后继续存活（新连接进不来：listener 已关）。原版 frpc 复现不了这种情况，
  作为剩余风险记录，不在这里测。

**源码看不出来、必须实测的**：

1. 心跳真的约每 10 秒一次、每次都到了探针。
2. 切到 `Ping` deny 之后 frpc 实际多久断开。按源码在 0 到约一个心跳间隔（10 秒）之间，取决于
   下一次心跳什么时候到。
3. 已打开的标签页是不是真的断了（浏览器可能自己重连，用户看到的可能是"卡一下又好了"）。
4. 只拒 Ping 时 frpc 是不是"反复连上又断开"；Login、NewProxy 也拒绝之后，设备是不是一直进不来，
   Login 的重试节奏是什么样。
5. 恢复之后多久回来。
6. frpc 不发心跳时，frps 是不是真的在约 30 秒后断开它（frps 侧兜底）。
7. 代价：探针整个停掉（模拟 authz 宕机）时，已在线的隧道是不是在一个心跳间隔内就被切断了。

**怎么做**：

要开四个终端：VPS 上的探针、VPS 上的 frps、OPNsense 上的 frpc，再加一个定义过 `w0modes` 的
VPS 终端。确认两台机器都开着 NTP；拿不准的话，时延只用 VPS 上的时间算（`w0modes` 的回显和
frps 日志的时间戳），frpc 的日志只用来看发生了什么。

**6.0 准备**：

- `w0modes '{}'`，frpc 在线（`start proxy success`），探针里 `Ping` 每 10 秒左右一条。记下本次
  运行第一条 Ping 的完整 body，以及相邻两条 Ping 的间隔（`距本 op 上一次 ... 秒`）。
- 手机或任意浏览器打开 `https://weekend0-test.router.example.com:8443`，登录，停在 Dashboard
  （标签页 A，实时图表在刷新）。

**6.1 只拒绝 `Ping`**：

- `w0modes '{"Ping":"deny"}'`，记下回显的时间 T0。
- 记录：
  - 探针：下一条 `op=Ping` 的时间，以及它是 `mode=deny 来源=file（...）`；
  - frps：`received invalid ping: denied by probe (PROBE_MODES_FILE[Ping]=deny, op=Ping)` 的时间 T1，
    随后 `client exit success` 的时间 T2；
  - frpc：`pong message contains error: denied by probe ...`；
  - 断线时延 = T2 − T0（也记一下 T1 − T0）；
  - 标签页 A：图表是否停住、点菜单是否报错或白屏、过一会儿是否自己恢复。
- 再看 1～2 分钟，记录 frpc 的行为。预计是 `try to connect to server...` →
  `login to server success` → `[opnsense-webui] start proxy success` → 很快又
  `pong message contains error`，反复。记下每一轮的间隔、探针里 `Login` / `NewProxy` / `Ping`
  计数怎么涨，以及重连时 Login 记录里的 `content.run_id`（预计一直是同一个旧 run id）。

**6.2 模拟"已撤销设备"：再把 Login 和 NewProxy 也拒掉**：

- `w0modes '{"Ping":"deny","Login":"deny","NewProxy":"deny"}'`。
- 至少观察 2 分钟，记录：
  - frpc 是否再也没有出现 `login to server success`；
  - `connect to server error: denied by probe (PROBE_MODES_FILE[Login]=deny, op=Login)` 的出现间隔
    （预计约 2、4、8、16 秒，之后稳定在 20 秒左右）；frps 每次对应一条 `register control error: ...`；
  - 探针里是不是只剩 `Login` 计数在涨；
  - 新开一个无痕窗口打开同一个地址：应该打不开（frps 上已经没有这个域名的路由）；
  - `curl -s -u '<webServer.user>:<webServer.password>' http://127.0.0.1:7500/api/proxy/https`：
    `opnsense-webui` 应为 `offline`，或者已经不在列表里。
- `NewUserConn` 不用写：设备不在线时，没有用户连接能走到这个钩子。

**6.3 恢复**：

- `w0modes '{}'`，记下时间 T3；frps 下一次 `new proxy [opnsense-webui] type [https] success` 的时间
  T4。恢复时延 = T4 − T3，按源码不超过 20 秒左右（重试间隔的上限）。刷新标签页 A，确认能恢复。

**6.4 重复测断线时延（一次性撤销）**：

- 如果最后采用 DESIGN §5 的候选主机制，生产上的撤销会是 authz 一次把这台设备的 `Ping`、`Login`、
  `NewProxy`（Q7 门控上线后还有 `NewUserConn`）全部拒掉（这个组合待本项数据，还没定）。
  这一步就模拟这种撤销。从全 `allow`、frpc 稳定在线开始，
  `w0modes '{"Ping":"deny","Login":"deny","NewProxy":"deny"}'`，按 6.1 的方法记 T0 和 T2，再按 6.3
  恢复。
- 至少重复 3 次（每次恢复后，等探针里出现 2 条以上 `mode=allow` 的 Ping 再撤），得到断线时延的
  范围。按源码，每次都不应超过一个心跳间隔（10 秒）多一点。

**6.5 frps 侧兜底：frpc 不发心跳时**：

- 停掉 frpc，把 `frpc.toml` 里的 `transport.heartbeatInterval = 10` 临时改成
  `transport.heartbeatInterval = -1`（`heartbeatTimeout` 不用动：interval 不大于 0 时 frpc 不检查它），
  `./frpc verify -c frpc.toml`，确认模式文件是 `{}`，再起 frpc。
- 预计：探针里不再有 `Ping`；frps 在 `new proxy [opnsense-webui] type [https] success` 之后约 30 秒
  记 `heartbeat timeout`，随后 `client exit success`；frpc 看到控制连接被关，自己断开重连，如此
  每 30 秒左右一轮。记录这几行的时间。
- 这验证的是：不靠 frpc 配合，frps 自己也会在 `heartbeatTimeout` 内断开一个"不报心跳"的客户端。
  被改过的 frpc 即使不理会带错误的 Pong，也逃不过这一条，因为被拒的 Ping 不刷新 `lastPing`——
  不过按源码，它只会失去控制连接和代理监听，已经打开的工作流可能继续存活（见上面的 (d)）。
- 测完把 `transport.heartbeatInterval` 改回 `10`，`./frpc verify -c frpc.toml`，重新起 frpc，确认
  探针里的 `Ping` 回来了。

**6.6 代价：控制面停掉时，已在线的隧道会不会被切断**：

- 从全 `allow`、frpc 在线、标签页 A 停在 Dashboard 开始。
- 在探针终端 Ctrl+C 停掉探针（模拟 authz 整个宕机），在另一个 VPS 终端记下时间 T5
  （`date '+%F %T.%3N'`）。
- 预计：下一次心跳（10 秒以内）frps 记 `send Ping request to plugin [nethub-probe] error: ...`
  （连接被拒）和 `received invalid ping: send Ping request to plugin error`，frpc 记
  `pong message contains error: send Ping request to plugin error` 并断开，标签页 A 断开；frpc 重连时
  Login 也问不到探针，`connect to server error: send Login request to plugin error`，按 20 秒上限一直
  重试。记下 frps `client exit success` 的时间 T6：断线时延 = T6 − T5。记下标签页 A 的表现。
- 停够 1 分钟，按第 1.6 步的命令重新起探针（模式文件还是 `{}`），记下时间 T7，以及 frps 下一次
  `new proxy [opnsense-webui] type [https] success` 的时间 T8：恢复时延 = T8 − T7（按源码不超过
  20 秒左右）。
- **不管结果如何都要记录**。如果实测是"探针一停，在线隧道约 10 秒内全断"，这就是 Ping 机制的
  代价：authz 宕机从"只挡新登录、新注册（订阅了 `NewUserConn` 时还挡新浏览器连接）"变成
  "所有在线设备一起断线"，必须进风险清单，authz 的高可用和超时设计要按这个级别来做。对照：
  不订阅 `Ping` 时，按源码 authz 停掉不影响已注册的隧道和已建立的连接（见③⑤）。想实测这个
  对照，可以临时从 `frps.toml` 的 `ops` 里去掉 `"Ping"`、重启 frps 再做一遍本步（可选，做完改回来）。

**6.6b 代价：控制面整体返回 500**：

- 从全 `allow`、frpc 在线、标签页 A 停在 Dashboard 开始，探针保持运行。
- `w0modes '{"Login":"error500","NewProxy":"error500","Ping":"error500"}'`，记下时间 T9。
- 预计和 6.6 一样：下一次心跳 frps 记 `received invalid ping`，frpc 记 `pong message contains error`
  并断开；重连时 Login 拿到 500，一直重试。记下断线时间 T10（断线时延 = T10 − T9）和标签页 A 的表现。
- 1 分钟后 `w0modes '{}'`，记下恢复时延（同 6.3 的算法）。

**6.6c 代价：控制面整体挂起**：

- 这一步要用长于心跳超时的 hang：趁 frpc 停着，用 `PROBE_MODES_FILE=/tmp/w0-modes.json PROBE_HANG_SECONDS=120 python3 probe.py`
  重启探针（模式文件先写成 `{}`），再起 frpc，等它稳定在线、标签页 A 停在 Dashboard。
- `w0modes '{"Login":"hang","NewProxy":"hang","Ping":"hang"}'`，记下时间 T11。
- 预计：这台设备的 Ping 卡在插件调用上，约 30 秒后两边记 `heartbeat timeout`，标签页 A 断开；
  重连的 Login 也会被挂起，而且同一 `run_id` 的重连要等旧连接上那次卡住的调用返回（见③里
  `WaitForHandoff` 的说明），所以在探针睡满 120 秒之前一直连不上。记下断线时间 T12（断线时延 = T12 − T11）。
- `w0modes '{}'`，等最后一个挂起的请求返回后，记下 frps 下一次 `new proxy [opnsense-webui] type [https] success`
  的时间。测完趁 frpc 停着，把探针按第 1.6 步的命令重启回默认的 `PROBE_HANG_SECONDS`。

6.6、6.6b、6.6c 三组合起来，就是 DESIGN §5 要的"后端整体停掉 / 返回 500 / 挂起"三种情况。

**6.7（可选）`Ping` 卡住**：

- `w0modes '{"Ping":"hang"}'`。预计：frps 卡在这次插件调用上（串行处理，这台设备后续的控制消息
  都排队），frpc 收不到 Pong；约 30 秒后 frpc 和 frps 两边都记 `heartbeat timeout` 并断开（frps 的
  `heartbeatWorker` 是单独的 goroutine，不受卡住的 handler 影响）。重连时同一 `run_id` 的新控制
  连接要等旧连接上那次卡住的 Ping 调用返回（`WaitForHandoff`，见③），所以重连会卡到探针睡满
  `PROBE_HANG_SECONDS` 为止，期间 frpc 反复报 Login 超时；之后的 Ping 又会被卡，如此循环，
  节奏由 `PROBE_HANG_SECONDS` 决定。记录实际断开和重新连上的时间，测完 `w0modes '{}'`。

**收尾**：`w0modes '{}'`，确认 frpc 在线、探针里 `Ping` 正常，`frpc.toml` 的 `heartbeatInterval`
已经改回 10。

**观察什么 / 判定**：

- 6.1 断开了，并且 6.2 设备一直进不来：主机制可行。6.4 的断线时延范围写进风险清单，作为
  Weekend 5"撤销 → 断线"时延目标的依据（DESIGN §10 W5：约 45 秒是目标，不是承诺）。
- 6.1 没断（frpc 没有 `pong message contains error`，或者有但会话没关）：主机制按现方案不可行，
  回到 DESIGN §5 看其他候选。下这个结论之前先排除配置问题：探针里有没有 `Ping`、那条 Ping 的
  mode 是不是 `deny`、第 1.5 步的 `transport` 检查是不是符合。
- 标签页 A 在 6.1 / 6.4 / 6.6 里断没断：断了，说明断线连带已打开的连接，撤销是真的断；没断，
  说明只挡住了新连接，DESIGN 不能写"撤销即断开"，已打开的页面还能用多久要另外记。
- 6.1 的"反复连上又断开"：每一轮代理都短暂注册过，说明撤销必须同时作用于 Login（authz 实现时
  撤销要对所有 op 生效），不能只拒 Ping。
- 6.5 frps 约 30 秒断开：frps 侧兜底成立。
- 6.6：authz 宕机对已在线隧道的影响和恢复时延，无论好坏都进风险清单。

**下一步**：结果填进 `results-template.md` 的⑥。心跳间隔的取舍也要一起记：间隔越短，撤销断得
越快，但 authz 要处理的 Ping 越多（N 台设备、间隔 T 秒，大约 N/T 次/秒），authz 宕机时所有隧道
断得也越快。DESIGN §5 的候选机制排序、§10 W5 的断线时延目标和风险清单，按实测结果回到
`docs/DESIGN.md` 去改，不在套件里改。

---

## 附：清理检查清单

验收全部做完之后，除了第 2.6 步 OPNsense 测试机上的清理，VPS 上也检查一遍：

- [ ] `frps`、`probe.py` 进程都已经 Ctrl+C 停掉（或者 `pkill frps`；
      `pkill -f probe.py`）。
- [ ] 验收项④的 443 基线已经清理：`openssl s_server` 已停，`/tmp/w0-baseline`
      （自签证书和私钥）已删，防火墙上临时放行的 TCP 443 已关。
- [ ] 如果为了验收④做了多网络的长时间采样，检查 VPS 的出站流量/日志没有
      异常告警（一般不会，但留意一下）。
- [ ] `probe.log` 保留下来作为验收项②⑤⑥的证据附件，不要删（也不要提交进仓库：
      里面有你的真实 IP 和域名，仓库的 `.gitignore` 忽略 `*.log`）。frps、frpc 终端里⑥用到的
      那几段日志（带时间戳）也一起存下来。
- [ ] 模式文件已删：`rm -f /tmp/w0-modes.json /tmp/w0-modes.json.tmp`。
- [ ] 如果⑥的 6.5 改过 `frpc.toml` 的 `transport.heartbeatInterval`，确认已经改回 `10`
      （或者这份临时副本已经按第 2.6 步删掉）；仓库里的 `frpc.toml` 不应该被改动。
- [ ] `frps.toml` 里填过的 `webServer` 用户名/密码、以及给 `frps.toml`/`frpc.toml`
      填过的真实 `auth.token`，确认没有被提交进任何 git 仓库（这份验证套件里的两份
      `.toml` 默认是 `CHANGE_ME` 占位、没配 `auth.token`，如果你自己改了，检查一下）。
- [ ] OPNsense 测试机上第 2.6 步的清理确实执行了（`frpc` 二进制、
      `frpc.toml`、解压出来的目录都删掉了）；如果测试机上装着 os-frp，确认它的
      配置和服务状态跟测试前一样。
- [ ] DNS 上加的泛解析记录：如果这台 VPS 只是临时借的、验证完就要退掉，
      记得把 DNS 记录也清掉或者更新指向。

## 附：把结果记录下来

六项验收的实测数据，包括配置检查的结果、③按 op 分开的 fail-open/fail-closed 结论、
④的 443 vs 8443 成功率/延迟样本和 Q2 规则的结论、⑤的 `NewUserConn` 观察、⑥的断线时延、
已打开页面的表现、重连/Login 表现和"控制面停机对在线隧道的影响"，填进同目录下的
`results-template.md`。
