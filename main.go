// nsnali: nslookup + nali 合体工具
//
// 用法:
//
//	nsnali [-s 223.5.5.5] [-t A,AAAA,CNAME,MX,NS,TXT] 域名...   // 解析并标注 IP 归属地
//	nsnali -ping www.baidu.com                                    // 解析后对每个 IP 做 ICMP 探测
//	nsnali -trace www.baidu.com                                   // 路由跟踪，每跳带归属地
//	nsnali -mtr 8.8.8.8                                           // 持续路由探测（Ctrl+C 停止）
//	nsnali -tcping -tcping-port 443 www.baidu.com                 // TCP 端口测延迟丢包
//	nsnali -ptr 8.8.8.8                                           // IP 反查域名
//	nsnali -asn 8.8.8.8                                           // ASN/运营商查询
//	nsnali -whois github.com                                      // WHOIS 注册信息
//	nsnali -cert www.baidu.com                                    // HTTPS 证书检查
//	nsnali -scan -scan-ports 22,80,443 1.1.1.1                     // 端口扫描（单 IP）
//	nsnali -scan -scan-ports 80,443 192.168.1.0/24                 // CIDR 段扫描
//	nsnali -scan AS15169                                          // ASN 扫描（AS→网段→代表主机）
//	dig www.qq.com | nsnali                                       // nali 模式：给文本里的 IP 加注释
//	nsnali 8.8.8.8 240e::1                                        // 参数是 IP 时直接查归属地
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"github.com/miekg/dns"
)

var ip2r *service.Ip2Region

// region 查询归属地，去掉 ip2region 结果里的 "0" 和空字段
func region(ip string) string {
	if ip2r == nil {
		return "未加载IP库"
	}
	r, err := ip2r.Search(ip)
	if err != nil || r == "" {
		return "未知"
	}
	var parts []string
	for _, p := range strings.Split(r, "|") {
		if p != "" && p != "0" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "未知"
	}
	return strings.Join(parts, " ")
}

func lookup(c *dns.Client, domain, server string, types []uint16) {
	fmt.Printf("Name:\t%s\n", domain)
	seen := map[string]bool{}
	for _, qt := range types {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), qt)
		m.RecursionDesired = true

		r, _, err := c.Exchange(m, server)
		if err == nil && r.Truncated { // 被截断时改用 TCP 重试
			tc := &dns.Client{Net: "tcp", Timeout: c.Timeout}
			r, _, err = tc.Exchange(m, server)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "** %s 查询失败: %v\n", dns.TypeToString[qt], err)
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			fmt.Printf("** %s: %s\n", dns.TypeToString[qt], dns.RcodeToString[r.Rcode])
			continue
		}
		for _, rr := range r.Answer {
			var line string
			switch v := rr.(type) {
			case *dns.CNAME:
				line = fmt.Sprintf("CNAME:\t%s", strings.TrimSuffix(v.Target, "."))
			case *dns.A:
				ip := v.A.String()
				line = fmt.Sprintf("Address: %s\t[%s]", ip, region(ip))
				if asnEnabled {
					line = appendASN(line, ip)
				}
				if ptrEnabled {
					line = appendPTR(line, ip)
				}
				if pcfg.enabled {
					line = appendPing(line, ip)
				}
				if tcfg.enabled {
					line = appendTrace(line, ip)
				}
				if tcpcfg.enabled {
					line = appendTCPing(line, ip)
				}
			case *dns.AAAA:
				ip := v.AAAA.String()
				line = fmt.Sprintf("Address: %s\t[%s]", ip, region(ip))
				if asnEnabled {
					line = appendASN(line, ip)
				}
				if ptrEnabled {
					line = appendPTR(line, ip)
				}
				if pcfg.enabled {
					line = appendPing(line, ip)
				}
				if tcfg.enabled {
					line = appendTrace(line, ip)
				}
				if tcpcfg.enabled {
					line = appendTCPing(line, ip)
				}
			case *dns.MX:
				line = fmt.Sprintf("MX:\t%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
			case *dns.NS:
				line = fmt.Sprintf("NS:\t%s", strings.TrimSuffix(v.Ns, "."))
			case *dns.TXT:
				line = fmt.Sprintf("TXT:\t%q", strings.Join(v.Txt, ""))
			default:
				line = rr.String()
			}
			if !seen[line] {
				seen[line] = true
				fmt.Println(line)
			}
		}
	}
}

// nali 模式：在文本中每个合法 IP 后面追加归属地
var ipRe = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}`)

func annotate(s string) string {
	return ipRe.ReplaceAllStringFunc(s, func(ip string) string {
		if net.ParseIP(ip) == nil {
			return ip
		}
		return fmt.Sprintf("%s [%s]", ip, region(ip))
	})
}

func naliMode() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		fmt.Println(annotate(sc.Text()))
	}
}

// IP 库下载源：优先 jsDelivr CDN 各节点，最后回退 GitHub 原始地址。
// 注：jsDelivr 对 GitHub 文件有 20MB 上限，v6 库（约 37MB）会被拒绝，自动走回退。
var mirrors = []string{
	"https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/",
	"https://fastly.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/",
	"https://gcore.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/",
	"https://testingcf.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/",
	"https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/",
}

// selfMirror 自建镜像（如你的 Caddy 文件服务器），排在最前面。
// 三种设置方式，优先级从高到低：-mirror 参数 > NSNALI_MIRROR 环境变量 > 编译时注入：
//
//	go build -ldflags "-X main.selfMirror=https://files.example.com/nsnali/" .
var selfMirror = ""

func mirrorList(flagVal string) []string {
	m := flagVal
	if m == "" {
		m = os.Getenv("NSNALI_MIRROR")
	}
	if m == "" {
		m = selfMirror
	}
	if m == "" {
		return mirrors
	}
	if !strings.HasSuffix(m, "/") {
		m += "/"
	}
	return append([]string{m}, mirrors...)
}

// dataDir 返回 IP 库存放目录：~/.cache/nsnali（Windows 为 %LocalAppData%\nsnali）
func dataDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "nsnali")
	}
	return "."
}

// findDB 依次在可执行文件目录、当前目录、缓存目录查找 xdb，都没有则返回缓存目录路径
func findDB(name string) string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	dirs = append(dirs, ".", dataDir())
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			return p
		}
	}
	return filepath.Join(dataDir(), name)
}

// download 按镜像顺序下载到 dst，先写临时文件，完整后再改名
func download(name, dst string, srcs []string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	var lastErr error
	skipJSD := false
	for _, base := range srcs {
		isJSD := strings.Contains(base, "jsdelivr.net")
		if isJSD && skipJSD {
			continue
		}
		url := base + name
		fmt.Fprintf(os.Stderr, "下载 %s ... ", url)
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			fmt.Fprintln(os.Stderr, "失败:", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			if isJSD && resp.StatusCode == http.StatusForbidden {
				skipJSD = true // 超过 jsDelivr 20MB 限制，其他节点同样会拒绝
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			fmt.Fprintln(os.Stderr, "失败:", lastErr)
			continue
		}
		tmp := dst + ".part"
		f, err := os.Create(tmp)
		if err != nil {
			resp.Body.Close()
			return err
		}
		n, err := io.Copy(f, resp.Body)
		resp.Body.Close()
		f.Close()
		if err != nil || (resp.ContentLength > 0 && n != resp.ContentLength) {
			os.Remove(tmp)
			lastErr = fmt.Errorf("下载不完整: %v", err)
			fmt.Fprintln(os.Stderr, "失败:", lastErr)
			continue
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "完成 (%.1f MB)\n", float64(n)/1024/1024)
		return nil
	}
	return fmt.Errorf("所有下载源均失败: %v", lastErr)
}

// ensureDB 文件不存在（或要求更新）时自动下载
func ensureDB(path, name string, update bool, srcs []string) {
	if !update {
		if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
			return
		}
	}
	if err := download(name, path, srcs); err != nil {
		fmt.Fprintf(os.Stderr, "%s 下载失败: %v\n", name, err)
	}
}

func parseTypes(s string) []uint16 {
	var out []uint16
	for _, t := range strings.Split(strings.ToUpper(s), ",") {
		if qt, ok := dns.StringToType[strings.TrimSpace(t)]; ok {
			out = append(out, qt)
		} else {
			fmt.Fprintf(os.Stderr, "忽略未知记录类型: %s\n", t)
		}
	}
	return out
}

func loadIP2Region(v4, v6 string) {
	v4cfg, err := service.NewV4Config(service.BufferCache, v4, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, "加载 IPv4 库失败:", err)
		return
	}
	var v6cfg *service.Config
	if v6 != "" {
		v6cfg, err = service.NewV6Config(service.BufferCache, v6, 1)
	}
	if v6 != "" && err != nil {
		fmt.Fprintln(os.Stderr, "加载 IPv6 库失败（仅 IPv4 可用）:", err)
		v6cfg = nil
	}
	ip2r, err = service.NewIp2Region(v4cfg, v6cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "初始化 ip2region 失败:", err)
		ip2r = nil
	}
}

func main() {
	server := flag.String("s", "223.5.5.5", "DNS 服务器，可带端口，如 8.8.8.8:53")
	qtypes := flag.String("t", "A,AAAA", "查询的记录类型，逗号分隔")
	timeout := flag.Duration("timeout", 3*time.Second, "查询超时")
	v4db := flag.String("v4", findDB("ip2region_v4.xdb"), "IPv4 xdb 路径（不存在则自动下载）")
	v6db := flag.String("v6", findDB("ip2region_v6.xdb"), "IPv6 xdb 路径（不存在则自动下载）")
	update := flag.Bool("update", false, "重新下载 IP 库后退出")
	noV6 := flag.Bool("no-v6", false, "不使用 IPv6 库（省去约 37MB 下载）")
	mirror := flag.String("mirror", "", "自建 IP 库下载地址（目录 URL），优先于 jsDelivr")
	doPing := flag.Bool("ping", false, "对解析出的 IP 执行 ICMP 探测并显示延迟/丢包")
	pingCount := flag.Int("ping-count", 3, "每个 IP 的 ping 次数")
	pingTimeout := flag.Duration("ping-timeout", 3*time.Second, "单次 ping 的超时")
	doTrace := flag.Bool("trace", false, "路由跟踪（TTL 递增），每跳标注归属地，需 root/CAP_NET_RAW")
	traceHop := flag.Int("trace-hop", 20, "trace 最大跳数")
	traceTimeout := flag.Duration("trace-timeout", 1*time.Second, "trace 每跳等待超时")
	doMTR := flag.Bool("mtr", false, "持续路由探测，累积每跳丢包/延迟统计，Ctrl+C 停止")
	mtrHop := flag.Int("mtr-hop", 20, "mtr 最大跳数")
	mtrCount := flag.Int("mtr-count", 3, "mtr 每跳每轮发包数")
	mtrRounds := flag.Int("mtr-rounds", 0, "mtr 轮数，0 表示持续到 Ctrl+C")
	mtrTimeout := flag.Duration("mtr-timeout", time.Second, "mtr 每跳等待超时")
	doTCPing := flag.Bool("tcping", false, "用 TCP 连接测延迟/丢包（ICMP 被禁时可用）")
	tcpPort := flag.Int("tcping-port", 80, "tcping 目标端口")
	tcpCount := flag.Int("tcping-count", 4, "tcping 连接次数")
	tcpTimeout := flag.Duration("tcping-timeout", 2*time.Second, "tcping 单次连接超时")
	doPTR := flag.Bool("ptr", false, "对 IP 反查 PTR 域名")
	doASN := flag.Bool("asn", false, "查询 IP 的 ASN/运营商信息（Team Cymru DNS）")
	doWHOIS := flag.Bool("whois", false, "WHOIS 查询域名/IP 注册信息")
	flag.BoolVar(&whoisFull, "whois-full", false, "WHOIS 显示原始全文")
	doCert := flag.Bool("cert", false, "检查 HTTPS 证书（颁发者/有效期/TLS 版本）")
	certPort := flag.Int("cert-port", 443, "证书检查端口")
	certTimeout := flag.Duration("cert-timeout", 3*time.Second, "证书检查超时")
	certInsecure := flag.Bool("cert-insecure", false, "证书检查跳过校验")
	doScan := flag.Bool("scan", false, "端口扫描（目标支持 IP/CIDR/范围/ASN）")
	scanPorts := flag.String("scan-ports", "21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,8080,8443", "扫描端口，逗号/范围")
	scanConcurrency := flag.Int("scan-concurrency", 100, "扫描并发数")
	scanTimeout := flag.Duration("scan-timeout", 800*time.Millisecond, "扫描单连接超时")
	scanMaxHosts := flag.Int("scan-max-hosts", 256, "CIDR/ASN 最多展开主机数")
	flag.Parse()

	pcfg = pingConfig{enabled: *doPing, count: *pingCount, timeout: *pingTimeout}
	tcfg = traceConfig{enabled: *doTrace, maxHop: *traceHop, probes: 2, timeout: *traceTimeout}
	mcfg = mtrConfig{enabled: *doMTR, maxHop: *mtrHop, count: *mtrCount, rounds: *mtrRounds, timeout: *mtrTimeout}
	tcpcfg = tcpingConfig{enabled: *doTCPing, port: *tcpPort, count: *tcpCount, timeout: *tcpTimeout}
	certcfg = certConfig{enabled: *doCert, port: *certPort, timeout: *certTimeout, insecure: *certInsecure}
	ptrEnabled = *doPTR
	asnEnabled = *doASN
	whoisEnabled = *doWHOIS
	scfg = scanConfig{enabled: *doScan, ports: *scanPorts, concurrency: *scanConcurrency, timeout: *scanTimeout, maxHosts: *scanMaxHosts}

	srcs := mirrorList(*mirror)
	ensureDB(*v4db, "ip2region_v4.xdb", *update, srcs)
	if !*noV6 {
		ensureDB(*v6db, "ip2region_v6.xdb", *update, srcs)
	}
	if *update {
		return
	}
	if *noV6 {
		*v6db = ""
	}

	loadIP2Region(*v4db, *v6db)
	if ip2r != nil {
		defer ip2r.Close()
	}

	if flag.NArg() == 0 {
		naliMode()
		return
	}

	srv := *server
	host, _, err := net.SplitHostPort(srv)
	if err != nil {
		host = srv
		srv = net.JoinHostPort(srv, "53")
	}
	fmt.Printf("Server:\t%s\t[%s]\n\n", srv, region(host))

	c := &dns.Client{Timeout: *timeout}
	dnsClient, dnsServer = c, srv
	types := parseTypes(*qtypes)
	for _, arg := range flag.Args() {
		// mtr 是持续全屏模式，单独运行每个目标后跳过其它探测
		if mcfg.enabled {
			target := arg
			if net.ParseIP(arg) == nil { // 域名：解析出首个 A 记录
				ips := resolveA(arg)
				if len(ips) == 0 {
					fmt.Printf("mtr: 无法解析域名 %s 的 A 记录\n", arg)
					continue
				}
				target = ips[0]
			}
			runMTR(target)
			continue
		}
		// scan 独立模式（IP / CIDR / 范围 / ASN）
		if scfg.enabled {
			fmt.Println(runScan(arg))
			continue
		}
		// tcping 独立模式（目标是域名时内部解析 A 记录）
		if tcpcfg.enabled && !pcfg.enabled && !tcfg.enabled {
			runTCPingOnly(arg)
			fmt.Println()
			continue
		}
		// whois 独立模式（对域名或 IP 查注册信息）
		if whoisEnabled && !pcfg.enabled && !tcfg.enabled && !certcfg.enabled {
			fmt.Println(appendWHOIS("", arg))
			fmt.Println()
			continue
		}
		// cert 独立模式（对域名/IP 检查证书）
		if certcfg.enabled && !pcfg.enabled && !tcfg.enabled && !tcpcfg.enabled {
			fmt.Println(certCheck(arg))
			fmt.Println()
			continue
		}
		if net.ParseIP(arg) != nil { // 参数本身是 IP，直接查归属地
			line := fmt.Sprintf("%s\t[%s]", arg, region(arg))
			if asnEnabled {
				line = appendASN(line, arg)
			}
			if ptrEnabled {
				line = appendPTR(line, arg)
			}
			if pcfg.enabled {
				line = appendPing(line, arg)
			}
			if tcfg.enabled {
				line = appendTrace(line, arg)
			}
			if tcpcfg.enabled {
				line = appendTCPing(line, arg)
			}
			fmt.Println(line)
			fmt.Println()
			continue
		}
		lookup(c, arg, srv, types)
		fmt.Println()
	}
}
