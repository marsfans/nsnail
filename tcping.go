package main

// tcping：用 TCP 连接代替 ICMP 测连通性和延迟。适合 ICMP 被防火墙禁止、
// 但 TCP 端口开放的场景（如 443/80）。基于 net.DialTimeout，无额外依赖。

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type tcpingConfig struct {
	enabled bool
	port    int
	count   int
	timeout time.Duration
}

var tcpcfg tcpingConfig

type tcpingStat struct {
	sent    int
	recv    int
	rtts    []float64
	target  string
	port    int
}

// appendTCPing 对目标（域名或 IP）做 TCP 连接测试，把结果追加到 line 后返回。
func appendTCPing(line, host string) string {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", tcpcfg.port))
	var b strings.Builder
	b.WriteString(line)
	fmt.Fprintf(&b, "\n  TCPing %s:", addr)

	st := tcpingStat{target: host, port: tcpcfg.port}
	for i := 0; i < tcpcfg.count; i++ {
		st.sent++
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, tcpcfg.timeout)
		if err != nil {
			fmt.Fprintf(&b, "\n    %d: 失败 (%v)", i+1, err)
			continue
		}
		rtt := float64(time.Since(start).Microseconds()) / 1000
		conn.Close()
		st.recv++
		st.rtts = append(st.rtts, rtt)
		fmt.Fprintf(&b, "\n    %d: connected %.1fms", i+1, rtt)
	}

	fmt.Fprintf(&b, "\n    %s tcp/%d: sent=%d received=%d loss=%.0f%%", host, tcpcfg.port, st.sent, st.recv, float64(st.sent-st.recv)/float64(st.sent)*100)
	if st.recv > 0 {
		min, max, sum := st.rtts[0], st.rtts[0], 0.0
		for _, r := range st.rtts {
			if r < min {
				min = r
			}
			if r > max {
				max = r
			}
			sum += r
		}
		fmt.Fprintf(&b, " min/avg/max = %.1f/%.1f/%.1fms", min, sum/float64(st.recv), max)
	}
	return b.String()
}

// runTCPingOnly 独立模式（目标为域名时解析其 A 记录逐个测；为 IP 时直接测）。
func runTCPingOnly(host string) {
	if net.ParseIP(host) == nil {
		ips := resolveA(host)
		if len(ips) == 0 {
			fmt.Printf("tcping: 无法解析域名 %s 的 A 记录\n", host)
			return
		}
		for _, ip := range ips {
			fmt.Println(appendTCPing("", ip))
		}
		return
	}
	fmt.Println(appendTCPing("", host))
}
