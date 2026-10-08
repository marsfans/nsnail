// nsnali: nslookup + nali 合体工具
//
// 用法:
//   nsnali [-s 223.5.5.5] [-t A,AAAA,CNAME,MX,NS,TXT] 域名...   // 解析并标注 IP 归属地
//   dig www.qq.com | nsnali                                       // nali 模式：给文本里的 IP 加注释
//   nsnali 8.8.8.8 240e::1                                        // 参数是 IP 时直接查归属地
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
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

// 默认在可执行文件同目录、当前目录查找 xdb
func defaultDB(name string) string {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return name
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
	v6cfg, err := service.NewV6Config(service.BufferCache, v6, 1)
	if err != nil {
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
	v4db := flag.String("v4", defaultDB("ip2region_v4.xdb"), "IPv4 xdb 路径")
	v6db := flag.String("v6", defaultDB("ip2region_v6.xdb"), "IPv6 xdb 路径")
	flag.Parse()

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
