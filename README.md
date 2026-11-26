# nsnali — nslookup + nali + ping + trace + mtr + tcping + ptr + asn + whois + cert + scan

> 🚀 **新更新：集成第三档 `-scan` 端口扫描，支持单 IP / CIDR / IP 范围 / ASN 四种目标，并发 TCP connect，按主机聚合开放端口并标注归属地。**
> 🚀 **v1.1.0 更新：IP 库首次运行自动下载，jsDelivr CDN 加速，支持自建镜像，无需手动准备 xdb。**

## 构建
    go mod download
    go build -o nsnali .

## IP 库（自动下载）
首次运行自动下载到缓存目录：`~/.cache/nsnali`（macOS: `~/Library/Caches/nsnali`，Windows: `%LocalAppData%\nsnali`）。

下载顺序：自建镜像 → jsDelivr（cdn / fastly / gcore / testingcf）→ GitHub raw。
jsDelivr 单文件限 20MB，v6 库约 37MB 会被拒，自动回退 GitHub。

自建镜像（如 Caddy 文件服务器）优先级：`-mirror` 参数 > `NSNALI_MIRROR` 环境变量 > 编译时注入：

    go build -ldflags "-s -w -X main.selfMirror=https://files.example.com/nsnali/" -o nsnali .

也可把 xdb 放在可执行文件同目录或当前目录，优先使用。

## 用法
    ./nsnali www.baidu.com                  # A + AAAA，带归属地
    ./nsnali -s 8.8.8.8 -t A,MX,TXT qq.com  # 指定服务器和记录类型
    ./nsnali 8.8.8.8                        # 直接查 IP
    dig qq.com | ./nsnali                   # nali 模式
    ./nsnali -update                        # 重新下载 IP 库
    ./nsnali -no-v6 qq.com                  # 只用 IPv4 库，免下 37MB
    ./nsnali -ping www.baidu.com            # 解析后 ping 每个 IP，显示延迟/丢包
    ./nsnali -ping -t A -ping-count 5 qq.com # 只 ping A 记录，发 5 个包
    ./nsnali -trace www.baidu.com           # 路由跟踪，每跳带归属地（需 root）
    sudo ./nsnali -trace -trace-hop 15 8.8.8.8  # 指定最大跳数
    sudo ./nsnali -mtr 8.8.8.8              # 持续路由探测，Ctrl+C 停止
    sudo ./nsnali -mtr -mtr-rounds 5 -mtr-count 3 223.5.5.5  # 只跑 5 轮
    ./nsnali -tcping -tcping-port 443 www.baidu.com  # TCP 443 测延迟丢包（无需 root）
    ./nsnali -ptr 8.8.8.8                   # 反查域名 → dns.google
    ./nsnali -asn 8.8.8.8                   # ASN 运营商 → AS15169 GOOGLE
    ./nsnali -whois github.com              # 注册商/创建/到期时间
    ./nsnali -whois -whois-full 8.8.8.8     # WHOIS 原始全文
    ./nsnali -cert www.baidu.com            # HTTPS 证书/有效期/TLS 版本
    ./nsnali -cert -cert-insecure 1.1.1.1   # 自签证书场景跳过校验
    ./nsnali -scan -scan-ports 22,80,443 1.1.1.1       # 单 IP 端口扫描
    ./nsnali -scan -scan-ports 80,443 192.168.1.0/24   # CIDR 段扫描
    ./nsnali -scan -scan-ports 80,443 192.168.1.1-100  # IP 范围扫描
    ./nsnali -scan -scan-ports 80,443 -scan-max-hosts 8 AS15169  # ASN 扫描

## Ping 功能实现

代码在 `ping.go`，`main.go` 只新增 3 个参数：`-ping`、`-ping-count`（默认 3）、`-ping-timeout`（默认 3s）。

双引擎设计：

1. **优先纯 Go ICMP**：用 `github.com/go-ping/ping`，`SetPrivileged(false)` 在 Linux 上走内核非特权 ping socket，无需 root，拿到精确的 min/avg/max 与丢包率。
2. **自动降级到系统 `ping`**：当内核禁用 ping socket（例如 `/proc/sys/net/ipv4/ping_group_range` 为 `1 0`）时，改用 `os/exec` 调用系统 ping，并用正则解析 Linux/macOS/Windows 的统计输出。

输出示例：

    Name:	www.baidu.com
    CNAME:	www.a.shifen.com
    Address: 180.101.49.44	[中国 江苏省 南京市 电信 CN]
      Ping:	延迟 min/avg/max = 7.3/7.4/7.5 ms, 丢包 0% [cmd]

`[cmd]` 表示走了降级引擎，`[icmp]` 表示纯 Go 引擎。

## Trace 功能实现

代码在 `trace.go`。用 `x/net/icmp` 的 raw socket 逐跳发送 TTL 递增的 ICMP Echo（TTL=1,2,3...），接收中间路由器返回的 **ICMP Time Exceeded**（type 11）来定位每一跳，收到 **Echo Reply** 说明到达目标即停止。关键处理：

- **包匹配**：从 Time Exceeded 携带的原始 IP 报文里解析出 Echo 的 ID/Seq，只认自己发的包，避免串包。
- **归属地**：每一跳的 IP 都调用项目已有的 `region()`，这是系统 `traceroute` 做不到的。
- **权限**：raw socket 需要 root 或 `CAP_NET_RAW`。普通用户授权一次即可免 sudo：

      sudo setcap cap_net_raw+ep ./nsnali

- **参数**：`-trace-hop`（默认 20 跳）、`-trace-timeout`（每跳默认 1s）。

> 部分网络环境中间节点可能会丢弃 TTL 过期包或不回 Time Exceeded，对应跳会显示 `*ms`，属正常现象。

输出示例：

      Trace to 223.5.5.5:
         1  169.254.68.5    [...]  0.4ms  0.3ms
         5  11.29.248.196   [United States ... US]  3.8ms  *ms

## MTR 功能实现

代码在 `mtr.go`，是 ping + trace 的融合版：持续对每一跳发包，累积统计丢包率和延迟（含 min/avg/max/StDev），Ctrl+C 停止时输出最终统计。复用了 `trace.go` 的 ICMP 探测与 ID/Seq 匹配、以及 `region()` 归属地查询。

- **参数**：`-mtr-hop`（最大跳数，默认 20）、`-mtr-count`（每跳每轮包数，默认 3）、`-mtr-rounds`（轮数，0 = 持续）、`-mtr-timeout`（每跳超时，默认 1s）。
- **权限**：同 trace，需 root 或 `CAP_NET_RAW`。
- 多轮累积统计让偶发丢包和抖动可见，比单次 trace 更适合排查网络质量问题。

## TCPing 功能实现

代码在 `tcping.go`，用 `net.DialTimeout` 建立 TCP 连接来测延迟和丢包，基于标准库、无需 root。当 ICMP 被防火墙禁止时（很多服务器的常见配置），ping 会误报不通，而 tcping 依然能测。

- **参数**：`-tcping-port`（默认 80）、`-tcping-count`（默认 4）、`-tcping-timeout`（默认 2s）。
- 可与其他探测组合：`-ping -tcping -tcping-port 443` 同时测 ICMP 和 TCP。
- 目标是域名时，内部用 `resolveA()` 解析 A 记录后逐个测。

## PTR 反向解析实现

代码在 `dns_ptr.go`，把 IP 转成反向域名（`in-addr.arpa` / `ip6.arpa`）后查 PTR 记录，复用已有 DNS 客户端。

- **参数**：`-ptr`。对直接输入的 IP 和解析出的 A/AAAA 记录都会反查，查不到显示 `PTR: -`。
- 实测：`8.8.8.8` → `dns.google`。

## ASN 查询实现

代码在 `asn.go`，通过 **Team Cymru 的 DNS 接口**查 IP 所属自治系统，复用已有 DNS 客户端，零新依赖、无需 API Key。

- 查询 `<反转IP>.origin.asn.cymru.com` 的 TXT，多条前缀时取最精确的一条；再查 `AS<号>.asn.cymru.com` 得到组织名。
- **参数**：`-asn`。对直接 IP 和解析出的 A/AAAA 都会查。
- 实测：`8.8.8.8` → `AS15169 GOOGLE - Google LLC, US [8.8.8.0/24 US arin]`；`1.1.1.1` → `AS13335 CLOUDFLARENET`。

## WHOIS 实现

代码在 `whois.go`，纯 Go 实现 RFC 3912 的 43 端口协议，不依赖系统 `whois` 命令。

- 先问 `whois.iana.org`，根据 `refer:` 递归跟进到权威服务器（最多 5 跳），再提取注册商、创建/更新时间、到期时间、状态、DNS 等关键字段。
- **参数**：`-whois`；`-whois-full` 显示原始全文。
- 实测：`github.com` → 注册商 Markmonitor Inc.，创建 2007-10-09，到期 2028-10-09。

## HTTPS 证书检查实现

代码在 `cert.go`，用标准库 `crypto/tls` 完成握手并读取证书链，零依赖。

- 显示颁发者、主题、有效期、剩余天数（含"即将过期/已过期"提示）、TLS 版本、SAN、证书链级数。
- **参数**：`-cert`、`-cert-port`（默认 443）、`-cert-timeout`（默认 3s）、`-cert-insecure`（跳过校验，用于自签证书）。
- 实测：`www.baidu.com` → TLS 1.2，GlobalSign 颁发，剩余 59 天，3 级证书链。

## 端口扫描实现

代码在 `scan.go`，并发 TCP connect 扫描（worker pool 控制并发），支持四种目标写法：

| 目标 | 示例 | 说明 |
|---|---|---|
| 单 IP | `1.1.1.1` | 直接扫描 |
| CIDR | `192.168.1.0/24` | 展开网段内主机（去掉网络/广播地址） |
| IP 范围 | `192.168.1.1-100` 或 `192.168.1.1-192.168.1.100` | 展开区间主机 |
| ASN | `AS15169` 或 `15169` | 通过 RIPEstat 查宣告网段，每个网段取代表主机 |

- **端口规格**：`-scan-ports` 支持逗号和范围，如 `22,80,443,8000-8080`；默认是常见端口列表。
- **参数**：`-scan-concurrency`（并发数，默认 100）、`-scan-timeout`（单连接超时，默认 800ms）、`-scan-max-hosts`（CIDR/ASN 最多展开主机数，默认 256，防止 ASN 主机爆炸）。
- **输出**：按主机聚合开放端口，并调用 `region()` 标注归属地。
- **ASN 数据源**：`https://stat.ripe.net/data/announced-prefixes/data.json`（免费无需 Key）。ASN 扫描只取每个网段的代表地址（网络地址+1），避免扫描整个 AS 的海量主机。

实测：`AS13335`（Cloudflare）展开网段→代表主机，逐个扫 443 并标注归属地正常。

## 发布
**打 tag 即自动发布**：推送 `v*` 版本的 tag 会自动触发 Release，编译并发布到同名 Release，说明自动取上一个 tag 以来的提交。

    git tag v1.2 && git push origin v1.2

Release 名称、产物版本号均取自 tag 名（如 `v1.2`），无需手动填版本号。

构建目标共 18 个（`.github/workflows/release.yml`）：

| 系统 | 架构 |
|---|---|
| Linux | amd64, arm64, **loong64（龙芯）**, **riscv64（RISC-V）** |
| Windows | amd64, arm64 |
| macOS | amd64, arm64 |
| FreeBSD / OpenBSD / NetBSD | amd64, arm64 |
| DragonFly BSD | amd64 |
| Solaris / illumos | amd64 |
| AIX | ppc64 |

均为 `CGO_ENABLED=0` 纯静态编译，已本地交叉编译验证全部通过。

Release 通过 GITHUB_TOKEN 调用 API 创建，无需额外配置。如需用 SSH deploy key 推送代码，已生成一对 ed25519 密钥：

- 公钥：`/workspace/nsnali_deploy_key.pub` —— 添加到仓库 Settings → Deploy keys（需要写权限时勾选 Allow write access）
- 私钥：`/workspace/nsnali_deploy_key` —— 妥善保管，不要提交到仓库

可在仓库 Settings → Variables 设 `NSNALI_MIRROR`，编译时注入自建 IP 库镜像。

## 更新日志
- v1.7.0：Release 扩展至 18 个构建目标（新增 Unix/BSD 与龙芯 loong64、RISC-V riscv64）
- v1.6.0：集成第三档 `-scan` 端口扫描，支持单 IP / CIDR / IP 范围 / ASN 四种目标，并发扫描与归属地标注
- v1.5.0：集成第二档网络工具——`-asn` / `-whois` / `-whois-full` / `-cert` / `-cert-port` / `-cert-insecure`
- v1.4.0：集成第一档网络工具——`-mtr` 持续路由探测、`-tcping` TCP 端口测速、`-ptr` 反向域名解析
- v1.3.0：新增 `-trace` / `-trace-hop` / `-trace-timeout`，逐跳路由跟踪并标注归属地
- v1.2.0：新增 `-ping` / `-ping-count` / `-ping-timeout`，双引擎 ICMP 探测（go-ping + 系统 ping 降级）
- v1.1.0：IP 库自动下载（jsDelivr CDN 加速 + GitHub 回退）、自建镜像（-mirror / NSNALI_MIRROR / ldflags）、-update、-no-v6
- v1.0.0：nslookup + nali，支持 A/AAAA/CNAME/MX/NS/TXT、截断转 TCP、nali 管道模式
