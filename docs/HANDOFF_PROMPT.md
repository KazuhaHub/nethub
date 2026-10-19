# NetHub 交接 Prompt

> 用法：把下面"Prompt 正文"整段复制，作为接手这个项目时的第一段话，发给接手的人，或者交给代她干活的编程助手。
> 这份文件和 `docs/PLAN.md` 一样是内部交接材料，**不要放进公开仓库**（PLAN.md 的决策 D12）。
> 写于 2026-10-16。项目状态一有变化，就要更新这里的"当前状态"一节。

---

## Prompt 正文

你接手的是 **NetHub**：一个开源、自己部署的路由器远程管理平台，第一版支持 OPNsense。
路由器上的插件主动连到你自己的中继服务器，中继只看 TLS 里的域名（SNI）就转发、不解密，
这样你在任何地方都能打开在 NAT 或 CGNAT 后面的路由器的管理页面。
项目负责人是 **Kazuha**。凡是要拍板的事都归他，你负责按计划执行，并拿出证据。

### 当前状态（2026-10-19）

- **Latest:** PR #58 enrollment, #59 server lifecycle and #60 native lifecycle merged as a3bc4da, b22c168 and 25c17e8 after six exact-head checks and inspected logs. Real native/public enrollment, manual/cron reports, removal, old-claim denial and verified restoration passed; see agents/opnsense/plugin/tests/w4-progress.md and deploy/validation-w4.md. Package 0.0.4 remains installed, original native field/runtime values and stopped intent restored, root/SSH/GUI security unchanged. All public test entries/timers are closed and original listeners restored. PR #61 merged as e9c5adb after six current-head checks and genuine expired-candidate replacement with verified TLS, retained history and both official clients. PR #62 adds isolated HTTP-01 publication and optional Caddy routing; its current checks are queued, so genuine proxy acceptance remains pending. The following account-client foundation uses the existing ACME SDK, bounded verified HTTPS and explicit current-terms consent; local protocol fixtures pass, but it creates no public account and is not integrated issuance. W4 trust acknowledgements/root rotation and GUI ACME plus W5-W7 remain open. Owner asleep: continue independent work without questions. Private continuation is nethub-w4-runtime/native-next.md.
- **Confirmed W4 scope:** D16/D19/W4-7 are recorded in w4-decisions.md. Certificate automation includes relay renewal/application and authenticated trust distribution, plus per-device router GUI certificate issuance, installation and renewal in v1. Console TLS belongs to the reverse proxy. The option-2 scope correction merged in PR #44 as ed771ca; implementation remains pending. See certificate-automation.md. W3's fresh Debian VM acceptance was confirmed on 2026-10-18. D13 release/signing and W7 disclosure/branch-protection decisions remain later gates.
- **W3 functional evidence complete:** source e27e908 passed a new Debian 13 guest deployment from zero Docker state, Docker-only initialization, the real Compose build/up, migrate exit zero, first-admin creation, scoped doctor, and nine real-public browser groups with public CA/hostname verification. CSP/script/external counts were zero. Four screenshots were reviewed and credentials were absent from runtime logs. The public window lasted 86.718s. See [the acceptance map and precise limits](../deploy/validation-w3.md). Main run 39192294899 passed all six jobs; check the closing PR's current state before W4 implementation.
- **Current operations:** original LXC OpenResty Docker and x-ui are restored on 80/443/8443. Owned W4 postgres/web/authz remain private and healthy. Caddy/frps and all source fixture/client/collector processes are stopped, 7000 is closed, and restoration timers were cancelled only after verification. Native public acceptance used the same retained authority and Caddy certificate state. Prior failed windows and the successful final receipt remain outside Git. OPNsense credentials and password SSH are unchanged.
- **W3 foundation:** actual-role PostgreSQL tests cover thirteen boundary groups, including tenant/member scope, forced RLS, column/function grants, one-use tokens, one-way revocation, audit, administrator races, and HTTP/session expiry races. React/shadcn/native dialog, embedded assets, first-admin CLI, init/backup acknowledgement, and Compose startup/failure gates pass. CI additionally runs the eleven-group real deployed browser suite. Full doctor runtime/relay/backup checks remain W7; full relay/appliance flows and SSO remain incomplete.
- **Version/security pins:** Go 1.26.9, frp 0.71.1, authcore v0.6.2. Rebuilt Caddy/PostgreSQL helpers and the runtime pass the three assembled-image HIGH/CRITICAL gate without exclusions. Go scans report zero affected symbols/imported packages; module-only advisory results are documented, not hidden. Current setup manifest is v2 with PostgreSQL UID 70; old UID-999 bundles are not silently migrated. See [security evidence](../deploy/security-validation.md).
- **Shared authentication:** authcore PR #30 merged as c5960e0 and was tagged v0.6.2. Its SAML replay cache retains live IDs under pressure and fails closed when full; signed-response/concurrency/race/API/scan CI passed. NetHub directly imports the module. Full SAML/OIDC routes and durable replay storage remain W6; reuse matching shared capabilities and improve reusable gaps upstream with a separate PR.
- **Platform boundary:** devices already have platform/capabilities and agents have separate directories. The old database constraint only accepts opnsense. W4 migration 00003 replaces it with bounded platform identifiers; cross-language contract and actual-role migration tests cover this boundary. The shared protocol remains platform-neutral. OPNsense is the only implemented/tested platform; no OpenWrt/VyOS agent is claimed.

- **Latest W2 state:** PR #23 merged as `43f9307` and implements independent frpc, strict TLS trust, safe reconcile, package-owned cron, and an independent one-attempt watchdog. Native tests cover live rollback/quarantine, WAN recovery (17.072s registration; 21.375s GUI), full relayed GUI, reboot, install/uninstall scheduling, and simultaneous os-frp use. Packaging PR #50 fixed disabled sample defaults overriding enabled services at boot; native reboot now starts both plugins automatically with unchanged legacy configuration hashes. Test settings were restored, temporary listeners closed, and private evidence archived. See [W2 validation](../agents/opnsense/plugin/tests/w2-progress.md). Kazuha confirmed the [W3 decisions](w3-decisions.md) on 2026-10-18, added SAML to v1, and required direct reuse of matching authcore packages. Reusable gaps may be improved in authcore. The W3 console evidence is recorded above; device/authz and SSO implementation remain later stages.

- **W2 tunnel integration is implemented and natively validated.** Device/authz and SSO remain unimplemented; the W3 console functional checks pass. GitHub 仓库是 <https://github.com/KazuhaHub/nethub>，2026-10-17 建好，**私有**。第一次提交 `f529e1d` 和之后的状态更新都已推送到 `main`。`main` has CI and weekly Actions dependency updates after PR #1 merged as `6612cdb`; branch protection is still unavailable on the current private-repository plan. Kazuha 已确认先保持私有，到 W7 再决定公开（【D2】）。
- 设计方案是 `docs/DESIGN.md` v0.3（中文），它是架构上的权威。
  执行计划是 `docs/PLAN.md`（中文），它把设计拆成按顺序做的任务：P0、W0–W7，再加缓冲。
- **W0 was accepted by Kazuha on 2026-10-18.** All six experiments are recorded in [the accepted report](../weekend0/results-2026-10-17.md), including the 1 GiB exception, A/B-only network scope, and backend-hang findings. D5/D6/D7/D17 are confirmed; D10/D20 and package metadata were confirmed; W1 native validation is recorded in the plugin tests directory.
- P0-4/P0-5: [PR #1](https://github.com/KazuhaHub/nethub/pull/1) merged with Kazuha's approval on 2026-10-17. PR pass/fail/pass evidence is linked there; the [main run](https://github.com/KazuhaHub/nethub/actions/runs/39026266818) also passed. The CLI workflow scope issue is resolved.
- P0-6 受平台限制：查询 `main` 生效规则时，GitHub API 返回 403，提示当前私有仓库需升级套餐或公开才能启用。保持私有，不更改可见性；分支保护尚未完成。
- W3-0: three UI samples, light/dark screenshots, bundle measurements, and strict-CSP interaction tests are complete. See [the comparison](ui-study/README.md). Default integrations all inject blocked styles; the shadcn/native-dialog adaptation passed the tested flows without CSP events. Kazuha confirmed shadcn/ui with native dialog for D9 on 2026-10-17. Sample source stays outside the product repository; the selected approach is used by the current React console.
- D3 topology: the local Windows machine hosts the OPNsense NAT client; the remote Debian LXC runs the server/relay. Windows restart and WHPX readiness passed, but complete GUI checks still failed with WHPX. The current native Hyper-V diagnostic uses a verified copy of the restored, updated disk with 1 GiB RAM and two vCPUs. QEMU and the abandoned LXC guest are off. Complete local and public desktop GUI checks now pass. The public window is closed and relay services are restored. W0 was accepted with its recorded limits on 2026-10-18; ①–⑤ pass within the approved scope; ⑥ measurements are complete; W0 was accepted by Kazuha on 2026-10-18.
- Local guest preparation history: LAN configuration, root-password replacement, SSH host-key verification, firmware update, and package-mirror TLS checks passed. Earlier Chrome checks established Dashboard containers and initial API responses, but not periodic updates. Complete local/public desktop diagnostics now pass on native Hyper-V as recorded below; mobile ① has now passed. The initial template warning did not recur during full regeneration; its original cause remains unproven.
- Firmware update: the stock minor update from 26.7 completed and the same disk booted successfully. OPNsense reports 26.7.7; the running kernel, installed kernel, and userland report FreeBSD 15.1-RELEASE-p4. The firmware process is absent, dedicated SSH passed with an unchanged host key, and package-mirror TLS verification passed after reboot. A converted copy of the restored disk-only snapshot now has boot verification, as recorded below. Raw evidence and credentials remain outside the repository.
- Image preparation: the official OPNsense 26.7 Nano image was verified against the pinned upstream announcement and release signature, converted to a 16 GiB dynamic VHDX, and transferred locally with a matching checksum. The source image required an update to at least 26.7.1_1; the current guest now meets that baseline at 26.7.7. The earlier [live boot](https://github.com/KazuhaHub/nethub/actions/runs/39026961946) and closed [installation experiment](https://github.com/KazuhaHub/nethub/pull/4) remain preparation only.
- Relay preparation: dedicated SSH access and wildcard DNS checks passed. Kazuha authorized temporarily stopping and restoring Xray and OpenResty during test windows. A temporary frp 0.71.0 transport preflight reached the earlier public test device's login form through the relay, with the same TLS leaf certificate as the device. Login and authenticated GUI operations were not tested. That public device cannot prove NAT traversal; the six W0 experiments remain unaccepted. The test processes and abandoned LXC guest are stopped, original listeners are restored, and test listeners are closed. Deployment details and raw evidence stay outside the repository.
- Local NAT relay preflight: the pinned FreeBSD frpc binary and both private configurations passed verification. A bounded public-relay window returned the local guest login form with a matching backend TLS leaf certificate. The owned client and relay test processes stopped afterward; original service listeners were rechecked and the restoration timer was cancelled. That earlier preflight did not establish authenticated GUI use or numbered W0 acceptance; current results follow below.
- The earlier packaging test device passed read-only readiness checks for OPNsense 26.7.7, os-frp 1.0.1, and frpc 0.71.0. Kazuha's revised permission to build, sign, and run NetHub on that designated host still applies; removing signing keys or build scratch is not required. It is not the selected NAT client for W0. Kazuha confirmed access to two mobile carriers and a company or campus network on 2026-10-17; A/B mobile samples now pass; Kazuha explicitly waived the company/campus sample.
- Additional local preflight: real frp 0.71.0 binaries passed both stock configuration checks and eight loopback transport/hook checks with the unmodified probe. Ping denial interrupted the local session in 9.55 seconds; NewUserConn deny and NewProxy deny/500 blocked access as expected. This does not verify OPNsense, NAT, public IP reporting, or carrier networks. The harness and results remain in the local `nethub-w0-local` directory.
- 这个项目 2026-09-17 暂停过，2026-10-16 恢复。暂停期间组织里的共享 Go 模块 `KazuhaHub/authcore` 已经做完（v0.6.1）。

GUI failure history (2026-10-17; current native Hyper-V result below): public desktop testing found HTTP_REFERER rejection on the relay-domain login POST. The error page included a logout link, so that link was a false-positive intermediate login predicate. Adding only the test hostname through the stock Administration form removed the rejection; DNS rebinding and HTTP_REFERER checks both remain enabled. Desktop checks then loaded Dashboard containers and initial API responses, but the mobile owner reported persistent loading. W0① was not accepted at that point. The earlier short AJAX-count increase did not prove periodic widget updates.

TCG showed load averages near 29 and queued backend tasks, with free guest RAM and no guest swapping. The loading root cause remains unproven.

The owner-authorized Windows restart is verified by its changed boot time; the WHPX capability API now reports available. The existing disk checksum matched the saved shutdown checkpoint before accelerated startup. Initial WHPX attempts had not reached root mount before termination; disabling legacy VGA and parallel ports alone did not resolve startup. They ended through QMP after zero writes on every block device and process exits were checked. With the userspace interrupt controller, the guest reached its shell in about 15 minutes. Dedicated public-key SSH passed with an unchanged host key. OPNsense 26.7.7, matching kernel and userland, and package-mirror TLS passed current-boot checks. The calibration warning remains, but a five-second sleep advanced guest wall and monotonic clocks by about five seconds; guest swap counters were zero. The disk and NAT layout are preserved, with no TCG fallback.

The full local GUI failed under WHPX. Later runs populated interface rows, charts, and EventSource messages, but system-information data and periodic clock updates did not pass; widget requests timed out. The failure reproduced without the public relay. A temporary CPU-affinity comparison did not resolve it; the original two-CPU mask was independently verified through the serial console afterward. The initial-wizard flag was cleared through the stock Abort button because network configuration and password replacement were already complete. XML comparison confirmed that all other settings were preserved, excluding revision metadata; the exact test hostname and both security checks remain correct.

The 3 GiB, two-vCPU WHPX VirtIO profile booted in about nine minutes and passed SSH, version, mirror TLS, and clock checks, but complete GUI checks still failed. Checksum, TSO, and LRO offloading were already disabled. A later host-CPU-model trial panicked in `devfs_find` and exited; its failed state was preserved before restoring the preceding disk-only snapshot. The safe generic-CPU launcher was restored. Do not repeat the host-CPU trial or infer guest health from older appended serial output.

The restored disk was converted to a separate VHDX and compared successfully against its source, including after clearing the host sparse-file flag required by Hyper-V. Its native Hyper-V boot passed dedicated SSH with the unchanged host key, current firmware/kernel/userland, mirror TLS, and clock checks. Synthetic NICs were verified by pinned MAC; LAN was preserved and WAN was configured through the stock console for host NAT. Local management forwards bind only to loopback. Complete local and public-relay GUI checks passed: populated system information, interfaces and charts, periodic clock updates, menu navigation, and zero widget, request, HTTP, or script errors, with the stock five-second widget timeout and both security checks unchanged. Public access returned the same backend TLS leaf certificate. Cleanup independently verified original listeners active and test listeners closed before cancelling the restoration timer. The temporary credential page remains closed. These 1 GiB desktop checks are preparation, not numbered W0 acceptance. On 2026-10-17, Kazuha explicitly approved continuing W0 with 1 GiB while recording the deviation from the documented 3 GiB VM minimum. Keep memory, swapping, and performance observations in the report; do not generalize this environment to production sizing. The converted snapshot copy has boot verification; the restored source QCOW2 has not been rebooted. Public desktop self-testing and mobile ① now pass. Experiments ②–④ also pass within the approved scope; ⑤/⑥ remain outstanding, as detailed below.


W0 progress (2026-10-17): experiment ① passed after the owner reported normal mobile login, Dashboard data, periodic refresh, menu navigation, and reload. Carrier, phone OS, and browser were left unrecorded at the owner's explicit request. The exact Alternate Hostnames entry was required; DNS rebinding and HTTP_REFERER checks remain enabled. Experiment ② passed using the fresh all-allow connection: Login metadata matches the configured top-level values, NewProxy `user.metas` matches Login, the requested subdomain matches, and the server-assigned NewProxy `user.run_id` is nonempty. The Login JSON omitted initial `client_id` and `run_id`. The control peer matched an independent connection through the same host NAT. See the [observed hook inputs](../proto/frp-hooks-0.71.0.md).

Experiment ③ passed six isolated fault groups: Login and NewProxy each with deny, HTTP 500, and a 120-second sleeping hook. Deny/500 prevented registration. The NewProxy sleeping request remained pending at 115 seconds while the frps admin API responded; heartbeat timeout was observed by the 35-second sample. Future requests were switched to allow at 110 seconds for recovery, without interrupting the existing sleep. At 125 seconds its delayed response had completed but the route was still unavailable; by 140 seconds registration and access had recovered. Login hang caused the client to exit and did not create a proxy after the delayed response. Restoring all allow recovered registration, access, and approximately ten-second heartbeats. Original relay services and listeners were independently verified after cleanup. These bounded observations found no fail-open and do not prove an infinite timeout.

Availability risk retained for review: a slow ownership hook blocks new registration; heartbeat timeout and control handoff can delay recovery even when frps itself remains responsive. Product hooks need bounded internal work and explicit failure handling. Decisions about NewUserConn/Ping gating and revocation latency still require ⑥ and the W0 review. Experiment ④ passes within the owner-approved two-mobile-network scope: A and B each returned TCP, TLS, and HTTP success in all 20 rounds on both ports, without triggering Q2. Company/campus sampling was explicitly waived by Kazuha and remains untested. See [the network report](../weekend0/network-results.md). Experiment ⑤ now passes; ⑥ measurements are complete; W0 was accepted by Kazuha on 2026-10-18. All results use the owner-approved 1 GiB exception, with no guest swapping in the recorded samples. Raw payloads, credentials, and deployment details stay outside the repository. W0 was accepted with the recorded limits on 2026-10-18; no product code has started.

Experiment ⑤ (2026-10-17): mobile source IPv4 matched NewUserConn remote_addr; proxy identity and device metadata matched registration. New connections were denied while the existing mobile Dashboard remained usable and control heartbeats stayed allowed. Desktop HTTP 500 and restored-allow checks passed. Original relay services were restored. See [the user-connection report](../weekend0/userconn-results.md). Experiment ⑥ measurements are complete; W0 was accepted by Kazuha on 2026-10-18.

### 第一步：按这个顺序读

1. `docs/PLAN.md` 的 §0–§6。尤其是 §0（怎么用这份计划）、§2（决策清单 D1–D22）、§4（红线和 git 规范）。
2. `docs/README.zh-CN.md`：项目的整体介绍。
3. `docs/DESIGN.md` 的 §0（变更记录）、§1、§2。
4. `CONTRIBUTING.md`：提交规范和开发环境。
5. 准备开始 W0 时，把 `weekend0/RUNBOOK.md` 通读两遍。

读完后，把看不懂的地方和发现的矛盾列成清单，发给 Kazuha。这是正常的第一步，不是打扰。

### 你第一周要做的事

1. **读文档，列问题**（见上）。
2. **Check the remaining readiness gates.** D1/D2 are confirmed; the D3 topology is selected, but mobile GUI acceptance has passed and two-mobile-network sampling now passes within the owner-approved scope:
   - 【D1】2026-10-17 已确认：保持 Apache-2.0，作为组织分层规则的例外，继续 P0；
   - 【D2】2026-10-17 已确认：仓库先保持私有，到 W7 再决定公开；
   - D3: use the local Windows OPNsense NAT client and remote LXC relay (PLAN §5.2). Native Hyper-V now passes complete local and public GUI diagnostics at 1 GiB. Kazuha approved continuing W0 at 1 GiB with the resource deviation recorded; preserve memory, swapping, and performance observations. Two mobile carriers and a company or campus network are available; A/B mobile samples now pass; Kazuha explicitly waived the company/campus sample. Keep access details outside the repository.
3. **按 PLAN §5 装好开发环境**，把每个工具的版本输出记下来。
4. **做 P0 剩下的部分**（PLAN §6，仓库已经建好）：最小 CI、Dependabot，请 Kazuha 开分支保护。先请 Kazuha 给你仓库的写权限。
5. **等测试资源的时候，可以先做 W3-0**：给 React 控制台做 2–3 个组件库示例，供 Kazuha 选（决策 D9）。这一步不需要任何测试资源。
6. **资源到位后做 W0**（PLAN §7，照 RUNBOOK 一步步来）。W0 没做完，不写任何安全相关的代码。

### 红线：绝对不能做的事

拿不准某件事算不算，就当它算，先问。

1. 不把真实域名、IP、端口、token、密码、密钥写进仓库、issue、PR、截图或聊天记录。一律用 `example.com`、`router.example.com`、`203.0.113.10`。
2. 不在任何生产路由器上装或运行 NetHub 的任何部分。
3. **The designated packaging test machine may build and sign packages while running NetHub** (DESIGN #20, revised by Kazuha on 2026-10-17). Removing signing keys or build/signing scratch, or relocating signing, is no longer required for that host. Other signing hosts remain outside scope.
4. 不构建、不签名、不发布正式软件包；不改打包仓库。需要改时，写清楚要改什么，交给 Kazuha。
5. 不 force push，不改写 git 历史，不直接推 `main`，所有改动走 PR。
6. 提交、PR、代码注释、分支名里不出现任何 AI 工具的署名或名字（例如 `Co-authored-by: …`、"Generated with …"）。提交用 `git commit -s`（DCO），用你自己的身份。
7. 不提交密钥文件（`.env`、`*.key`、`*.pem`、`deploy/secrets/`），不用 `git add -f`。
8. 改 `proto/` 必须在同一个 PR 里：改版本号、改所有受影响的 agent、更新契约测试、写兼容性影响。
9. **DESIGN 里标「建议」或「待定」的东西，都不是已经决定的事。** 动手前先看 PLAN §2 的决策清单有没有结论。

### 决策：哪些不能你自己定

PLAN §2 列了 D1–D22，**全部归 Kazuha 拍板**。你的职责有三件：

- 到了"最晚什么时候定"还没有结论，就停在那一步；
- 把需要的信息整理好，交给他；
- 他做了决定，就记进决策记录（模板见 PLAN 附录 E）。

几类最常遇到的：

- **开工前决策：** D1、D2 已确认（见上），可继续 P0；D3 uses the topology above; do not accept W0 until the guest and external-network checks pass. W1 之前还要定 D10（插件目录结构）和 D20（打包仓库里的文件能不能复制，涉及版权）。
- **等 W0 结果再定：**
  - D5：要不要把 8443 换成 443；
  - D6：撤销时怎么断开在线隧道；
  - D7：设备登录页的公网暴露要不要加门禁；
  - D17：OPNsense 自己的主机名检查。
- **v1 发布前必须解决：** D22（设备到中继的控制通道还没有服务端认证，见下面"已知的坑"第 5 条）。

### 已知的坑

这些都是之前核对源码或文档时发现的。先读一遍，到对应阶段再回来看。

1. **TOML 表的作用域。** 写在 `[transport]`、`[[proxies]]` 这类表头下面的键，会归到那张表里。所有顶层键必须写在第一个表头之前。frp 默认 `strict_config`，放错位置直接报错退出。
2. **W0 期间不要靠重启探针来切模式。** frps 订阅了 `Ping`，探针一停，在线隧道就会断。切模式用模式文件（RUNBOOK 1.6 的 `w0modes`）。做第 ③ 项的 hang 组时，用 `PROBE_HANG_SECONDS=120`，不要用默认的 30。
3. **OPNsense 自己的 DNS 重绑定 / HTTP_REFERER 检查**，很可能会拦下经中继的访问（DESIGN Q9）。看到错误页先别判定"穿透失败"：把测试子域名加进 OPNsense 的"Alternate Hostnames"再测，**不要关掉这两项检查**。
4. **经中继访问时，设备看到的客户端地址可能都是 `127.0.0.1`。** 这会影响 OPNsense 自己的登录锁定和日志，W0 时顺便确认。
5. **frpc 默认不校验 frps 的证书**（DESIGN Q10，对照 frp 0.71.0 源码确认过）：只开 `transport.tls.enable`、不配 `trustedCaFile` 时，什么证书都接受。W0 测试可以先这样，但产品里必须按 D22 的结论修好。
6. **OPNsense 插件的钩子文件名要用下划线**：`plugins.inc.d/nethub_agent.inc`。用连字符的话，钩子函数不会生效。
7. **reconcile 发现配置内容没变时**，也要检查服务有没有在运行；该运行却没运行，就把它启动。
8. **authz 的 `NewProxy` 校验必须拒绝任何 custom domain。** 否则任何一台设备都能注册控制台自己的域名，拿到管理员的控制台 cookie（DESIGN §5）。
9. **Postgres 的 `SECURITY DEFINER` 函数，默认谁都能执行。** 要先对 PUBLIC 收回执行权限，再单独授权给 `nethub_authz`。
10. **租户设置必须用事务内有效的写法**（`set_config(..., true)`），否则连接池里的连接会把上一个请求的租户带给下一个请求。
11. **`go.work` 陷阱**：仓库上级目录有 `go.work` 时，Go 命令前要加 `GOWORK=off`。
12. **测试机和"NAT 后面的家用路由器"不一样**（PLAN §5.2）：GUI 不在 443，`frpc.toml` 的 `localPort` 要改；
    它有公网 IP，GUI 端口在 WAN 上对外开放，做 W0 ① 之前要请 Kazuha 把这条规则限制成只允许你的 IP；它可能没有快照，测完按清理清单恢复。
13. **D4 confirmed 2026-10-18:** coordinate the os-frp, NetHub frpc, and frps upgrade to 0.71.1 before W2 integration. Keep historical W0 evidence at 0.71.0. Build-time official downloads with fixed SHA256 are approved. D22 uses a deployment CA, trustedCaFile and serverName, without mounting the CA private key in runtime containers. D21 omits newwanip and requires measured WAN-address recovery in W2; failed automatic recovery requires a debounced hook and a repeated test.

### 怎么工作

- **一个任务一个分支、一个小 PR。** PR 描述用 PLAN 附录 B 的模板，写清楚做了什么、为什么、怎么验证的，并附上证据（日志、截图、命令输出，真实地址打码）。
- **验收项必须有证据才能打勾。** 没测过的就写"没测过"，失败了就贴失败的输出。
- **卡住超过 2 小时就问。** 按 PLAN 附录 D 的提问模板写：你想做什么、做了哪些步骤、预期是什么、实际看到什么、你的猜测。
- **每天发一条三行的日报**（PLAN 附录 C）：做了什么、卡在哪、明天做什么。每个阶段结束发阶段总结，并和 Kazuha 一起重新估剩下的工作量。
- **每次 push 前跑一遍 PLAN 附录 F 的自查脚本**，检查有没有真实地址、密钥、AI 署名。
- **PLAN 和 DESIGN 说法不一致时，以 DESIGN 为准**，并告诉 Kazuha，由他决定改哪一份。
- **计划里没写到的情况，不要自己猜一个方案就做下去。** 先问。

### 文件地图

| 文件 | 是什么 |
|---|---|
| `docs/PLAN.md` | 执行计划：阶段、任务、验收、决策清单、模板（内部） |
| `docs/DESIGN.md` | 设计方案 v0.3，架构上的权威（中文） |
| `docs/threat-model.md` | 威胁模型初稿（英文），W0 之后和 W7 要更新 |
| `docs/console-api.md` | 控制台 API 草稿（英文），W3 起实现时同步修改 |
| `docs/README.zh-CN.md` | README 的中文版，英文 README 一改就要同步 |
| `weekend0/` | W0 的操作手册、结果模板、探针、frp 配置 |
| `server/`、`deploy/`、`proto/`、`agents/opnsense/` 下的 README | 各组件的规划，还没有代码 |
| `CONTRIBUTING.md` | 提交规范（DCO、Conventional Commits）、开发环境 |

还没写的文档有两份。`docs/protocol.md` 和 `proto/` 下的 JSON Schema 在 W4 写，要用 W0 实测出的字段名。`docs/deployment.md` 在 W7 写，要等部署脚本真正写出来。

### 第一件事

读完上面列的文档后，给 Kazuha 发一条消息，包括三部分：

1. 你的问题清单；
2. 请他定 D1、D2、D3；
3. 你打算这一周做什么。

然后开始按 PLAN §5 装环境。

### Dedicated test device verification (2026-10-17)

Kazuha supplied and approved the dedicated non-production test device. The subsequent 2026-10-17 rule permits package building, signing, and NetHub use on this same host; the earlier key-removal prerequisite is superseded. SSH access and read-only checks passed: installed UFS root, OPNsense 26.7.7, FreeBSD 15.1-RELEASE-p4 amd64, Python 3.13.15, os-frp 1.0.1, and frpc 0.71.0. No frpc process was running. The stock W0 client configuration passed strict validation, and the temporary copy was removed. Firmware and services were unchanged. Relay SSH and wildcard DNS were subsequently verified; carrier-network tests remain open. The local NAT guest is now selected for W0; this earlier device check is not W0 acceptance. Access details and SSH private key material remain outside the repository.


W0 review readiness (2026-10-17): all six experiments now have measurements.
Three repeated combined Ping/Login/NewProxy denial trials disconnected the stock
client after 2.136, 3.032, and 4.958 seconds. Disabling client heartbeats produced
server timeouts about 30 seconds after registration. Backend process loss and
HTTP 500 interrupted registered tunnels and blocked re-registration. The
120-second backend hang exposed stale admin online status after heartbeat timeout
and intermittent recovery; it must not be described as a clean 30-second revoke.
Private evidence, failed/interrupted attempts, and a review draft are preserved
outside Git. Kazuha accepted W0 and D5/D6/D7/D17 on 2026-10-18; no product work
has started. Original relay services/listeners were independently verified
restored, owned test processes and tracked temporary stages removed after private
archival, and the Mac download publication removed. The updated local diagnostic
VM is retained; no Hyper-V checkpoint exists to restore. The W0 review is complete. Product implementation
must pass the separate W1 gates.


W0 acceptance (2026-10-18): Kazuha accepted the six measured experiments and
recorded limits, confirmed D5/D6/D7/D17, and authorized the DESIGN update and
progression through the W1 gates. See [accepted results](../weekend0/results-2026-10-17.md).
No product code exists yet; D10/D20 and package metadata remain W1 decisions.


W1 decisions (2026-10-18): Kazuha confirmed D10/D20, independent source and
standalone unsigned development packaging, without kazuha.sh mirror. Release
recipe integration remains deferred. Public product_email is admin@kazuha.org
(the owner input used a full-width dot, normalized to an ASCII dot); product_website
is https://github.com/KazuhaHub/nethub. A clean powered-off Hyper-V checkpoint
was created before installing the development plugin. Implementation is in progress.


W1 validation (2026-10-18): the unsigned development skeleton passed native build,
installation, enabled save, uninstall with retained settings, and reinstall on
OPNsense 26.7.7. Firmware registration cleanup was fixed and retested. See
[the evidence](../agents/opnsense/plugin/tests/native-validation.md). The plugin
remains installed for W2 and starts no tunnel. D4/D21/D22 and the pinned-download
choice were confirmed on 2026-10-18; coordinate the 0.71.1 upgrade before W2 integration. Test access was simplified
at the owner's request; credentials remain outside Git.

W2 update (2026-10-18): draft PR #23 implements the independent service, validated reconcile, and GUI debug interface. Native partial evidence is in plugin/tests/w2-progress.md. Kazuha confirmed package-owned cron.d entries, shared nonblocking lockf, persistent rollback quarantine, and local revoked suppression under W2-7. Cron lifecycle, full coexistence, reboot, and WAN-address recovery remain acceptance work; do not report W2 complete.
