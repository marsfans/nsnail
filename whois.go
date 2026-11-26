package main

// WHOIS 查询：纯 Go 实现 RFC 3912 的 43 端口协议。
// 流程：先问 whois.iana.org 拿到 refer（或按 TLD/IP 直接选服务器），
// 再递归跟进 refer 指向的权威服务器，最后提取关键字段。
// 不依赖外部 whois 命令。

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// whoisQuery 向单个 whois 服务器发查询并返回原始文本。
func whoisQuery(server, query string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	var b strings.Builder
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		b.WriteString(sc.Text())
		b.WriteString("\n")
	}
	return b.String(), sc.Err()
}

// whoisFetch 递归跟进 refer，返回最终权威服务器的原文和使用的服务器。
func whoisFetch(query string, timeout time.Duration) (string, string) {
	server := "whois.iana.org"
	for i := 0; i < 5; i++ {
		text, err := whoisQuery(server, query, timeout)
		if err != nil {
			return fmt.Sprintf("WHOIS 查询失败 (%s): %v", server, err), server
		}
		// 找 refer / whois 服务器跳转
		next := whoisRefer(text)
		if next == "" || strings.EqualFold(next, server) {
			return text, server
		}
		server = next
	}
	// 达到最大跳数，再查一次当前服务器
	text, _ := whoisQuery(server, query, timeout)
	return text, server
}

// whoisRefer 从 whois 文本中提取 refer / Registrar WHOIS Server。
func whoisRefer(text string) string {
	re := regexp.MustCompile(`(?im)^\s*(?:refer|registrar whois server|whois server)\s*:\s*(\S+)`)
	m := re.FindStringSubmatch(text)
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var (
	reRegistrar  = regexp.MustCompile(`(?im)^\s*registrar\s*:\s*(.+)$`)
	reCreation   = regexp.MustCompile(`(?im)^\s*(?:creation date|created|registered on)\s*:\s*(.+)$`)
	reExpiry     = regexp.MustCompile(`(?im)^\s*(?:expir\w* date|expires on|paid-till|registrar registration expiration date)\s*:\s*(.+)$`)
	reUpdated    = regexp.MustCompile(`(?im)^\s*(?:updated date|last modified|changed)\s*:\s*(.+)$`)
	reStatus     = regexp.MustCompile(`(?im)^\s*(?:domain status|status)\s*:\s*(.+)$`)
	reNameServer = regexp.MustCompile(`(?im)^\s*(?:name server|nserver)\s*:\s*(.+)$`)
)

// whoisSummary 从原文提取关键字段摘要。
func whoisSummary(text, server string) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("  WHOIS (%s):", server))
	add := func(label string, re *regexp.Regexp, limit int) {
		m := re.FindAllStringSubmatch(text, -1)
		if len(m) == 0 {
			return
		}
		var vals []string
		seen := map[string]bool{}
		for _, x := range m {
			v := strings.TrimSpace(x[1])
			if v != "" && !seen[v] {
				seen[v] = true
				vals = append(vals, v)
			}
			if limit > 0 && len(vals) >= limit {
				break
			}
		}
		lines = append(lines, fmt.Sprintf("    %-14s %s", label+":", strings.Join(vals, ", ")))
	}
	add("注册商", reRegistrar, 1)
	add("创建时间", reCreation, 1)
	add("更新时间", reUpdated, 1)
	add("到期时间", reExpiry, 1)
	add("状态", reStatus, 3)
	add("DNS", reNameServer, 4)
	if len(lines) == 1 {
		lines = append(lines, "    (未提取到标准字段，原文见 -whois-full)")
	}
	return strings.Join(lines, "\n")
}

var (
	whoisFull    bool
	whoisEnabled bool
)

// appendWHOIS 对域名或 IP 做 WHOIS 查询，结果追加到 line 后返回。
func appendWHOIS(line, target string) string {
	text, server := whoisFetch(target, 5*time.Second)
	if whoisFull {
		return line + "\n" + indentText("  WHOIS raw ("+server+"):", text)
	}
	return line + "\n" + whoisSummary(text, server)
}

func indentText(header, text string) string {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) != "" {
			b.WriteString("    " + l + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
