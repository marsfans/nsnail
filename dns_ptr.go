package main

// DNS 辅助：反向 PTR 查询（IP → 域名）与正向 A 记录解析（tcping 用）。
// 复用 main.go 的 DNS 客户端与服务器设置。

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

var (
	dnsClient  *dns.Client
	dnsServer  string
	ptrEnabled bool
)

// reverseName 把 IP 转成反向解析域名。
// IPv4: 1.2.3.4 -> 4.3.2.1.in-addr.arpa.
// IPv6: 每 nibble 反转 -> .ip6.arpa.
func reverseName(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := p.To16()
	hex := fmt.Sprintf("%x", v6)
	var parts []string
	for i := len(hex) - 1; i >= 0; i-- {
		parts = append(parts, string(hex[i]))
	}
	return strings.Join(parts, ".") + ".ip6.arpa."
}

// reversePTR 反查一个 IP 的 PTR 记录，返回第一个域名；查不到返回空。
func reversePTR(ip string) string {
	name := reverseName(ip)
	if name == "" || dnsClient == nil {
		return ""
	}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypePTR)
	m.RecursionDesired = true
	r, _, err := dnsClient.Exchange(m, dnsServer)
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return ""
	}
	for _, rr := range r.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			return strings.TrimSuffix(ptr.Ptr, ".")
		}
	}
	return ""
}

// appendPTR 把反向域名追加到 line 后返回。
func appendPTR(line, ip string) string {
	host := reversePTR(ip)
	if host == "" {
		return line + "\n  PTR:\t-"
	}
	return line + fmt.Sprintf("\n  PTR:\t%s", host)
}

// resolveA 解析域名的 A 记录，返回 IPv4 列表（tcping 用）。
func resolveA(domain string) []string {
	if dnsClient == nil {
		return nil
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true
	r, _, err := dnsClient.Exchange(m, dnsServer)
	if err != nil || r == nil {
		return nil
	}
	var ips []string
	seen := map[string]bool{}
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			s := a.A.String()
			if !seen[s] {
				seen[s] = true
				ips = append(ips, s)
			}
		}
	}
	return ips
}
