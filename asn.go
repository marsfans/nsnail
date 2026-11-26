package main

// ASN 运营商查询：通过 Team Cymru 的 DNS 接口查询 IP 所属的自治系统（AS），
// 完全复用已有 DNS 客户端，零新依赖、无需 API Key。
// 查询格式：<反转IP>.origin.asn.cymru.com 的 TXT 记录
// 返回格式：AS号 | 网段 | 国家 | 注册局 | 分配日期
// 再查 AS<号>.asn.cymru.com 得到 AS 名称（组织）。

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

var asnEnabled bool

type asnInfo struct {
	AS        string
	Prefix    string
	Country   string
	RIR       string
	Date      string
	Name      string
	prefixLen int
}

// reverseOriginName 生成 Team Cymru origin 查询域名。
// IPv4: 1.2.3.4 -> 4.3.2.1.origin.asn.cymru.com
// IPv6: 每 nibble 反转 -> .origin6.asn.cymru.com
func reverseOriginName(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com.", v4[3], v4[2], v4[1], v4[0])
	}
	hex := fmt.Sprintf("%x", p.To16())
	var parts []string
	for i := len(hex) - 1; i >= 0; i-- {
		parts = append(parts, string(hex[i]))
	}
	return strings.Join(parts, ".") + ".origin6.asn.cymru.com."
}

// queryTXT 查一条 TXT 记录，返回拼接后的文本。
func queryTXT(name string) string {
	if dnsClient == nil {
		return ""
	}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	m.RecursionDesired = true
	r, _, err := dnsClient.Exchange(m, dnsServer)
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return ""
	}
	for _, rr := range r.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			return strings.Join(txt.Txt, "")
		}
	}
	return ""
}

// lookupASN 查询 IP 的 ASN 信息，取最精确（最长前缀）的一条。
func lookupASN(ip string) *asnInfo {
	name := reverseOriginName(ip)
	if name == "" {
		return nil
	}
	txt := queryTXT(name)
	if txt == "" {
		return nil
	}
	// 可能有多条 TXT（不同前缀），取最后一条（通常最精确），用独立查询不便，
	// 这里 queryTXT 返回第一条；用 queryAllTXT 取前缀最长的。
	lines := queryAllTXT(name)
	var best *asnInfo
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			continue
		}
		as := strings.TrimSpace(parts[0])
		prefix := strings.TrimSpace(parts[1])
		country := strings.TrimSpace(parts[2])
		rir := strings.TrimSpace(parts[3])
		date := ""
		if len(parts) >= 5 {
			date = strings.TrimSpace(parts[4])
		}
		// 用 CIDR 掩码位比较精确程度
		prefixLen := 0
		if i := strings.Index(prefix, "/"); i >= 0 {
			fmt.Sscanf(prefix[i+1:], "%d", &prefixLen)
		}
		if best == nil || prefixLen > best.prefixLen {
			best = &asnInfo{AS: as, Prefix: prefix, Country: country, RIR: rir, Date: date, prefixLen: prefixLen}
		}
	}
	if best == nil && txt != "" {
		// 兜底：只有一条时按单条解析
		parts := strings.Split(txt, "|")
		if len(parts) >= 4 {
			best = &asnInfo{
				AS: strings.TrimSpace(parts[0]), Prefix: strings.TrimSpace(parts[1]),
				Country: strings.TrimSpace(parts[2]), RIR: strings.TrimSpace(parts[3]),
			}
			if len(parts) >= 5 {
				best.Date = strings.TrimSpace(parts[4])
			}
		}
	}
	if best == nil {
		return nil
	}
	// 查 AS 名称
	asNum := strings.TrimPrefix(best.AS, "AS")
	detail := queryTXT(fmt.Sprintf("AS%s.asn.cymru.com.", asNum))
	if detail != "" {
		// 格式：AS号 | 国家 | 注册局 | 日期 | 组织名
		if d := strings.Split(detail, "|"); len(d) >= 5 {
			best.Name = strings.TrimSpace(d[4])
		}
	}
	return best
}

// queryAllTXT 返回某域名的所有 TXT 记录文本。
func queryAllTXT(name string) []string {
	if dnsClient == nil {
		return nil
	}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	m.RecursionDesired = true
	r, _, err := dnsClient.Exchange(m, dnsServer)
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return nil
	}
	var out []string
	for _, rr := range r.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(txt.Txt, ""))
		}
	}
	return out
}

// appendASN 把 ASN 信息追加到 line 后返回。
func appendASN(line, ip string) string {
	info := lookupASN(ip)
	if info == nil {
		return line + "\n  ASN:\t-"
	}
	s := fmt.Sprintf("AS%s", strings.TrimPrefix(info.AS, "AS"))
	if info.Name != "" {
		s += " " + info.Name
	}
	s += fmt.Sprintf(" [%s %s %s]", info.Prefix, info.Country, info.RIR)
	return line + "\n  ASN:\t" + s
}
