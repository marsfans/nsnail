// nsnali: nslookup + nali 合体工具
//
// 用法:
//
//	nsnali [-s 223.5.5.5] [-t A,AAAA,CNAME,MX,NS,TXT] 域名...   // 解析并标注 IP 归属地
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
				line = fmt.Sprintf("Address: %s\t[%s]", v.A, region(v.A.String()))
			case *dns.AAAA:
				line = fmt.Sprintf("Address: %s\t[%s]", v.AAAA, region(v.AAAA.String()))
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
	flag.Parse()

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
	types := parseTypes(*qtypes)
	for _, arg := range flag.Args() {
		if net.ParseIP(arg) != nil { // 参数本身是 IP，直接查归属地
			fmt.Printf("%s\t[%s]\n\n", arg, region(arg))
			continue
		}
		lookup(c, arg, srv, types)
		fmt.Println()
	}
}
