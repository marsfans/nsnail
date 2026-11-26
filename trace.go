package main

// 本文件给 nsnali 增加 traceroute 能力：
// 用 x/net/icmp 逐跳发送 TTL 递增的 ICMP Echo，收集 Time Exceeded / Echo Reply，
// 并复用 main.go 的 region() 给每一跳标注归属地（这是本工具区别于系统 traceroute 的地方）。
// 需要 root 或 CAP_NET_RAW 权限；普通用户可用 setcap 授权。

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type traceConfig struct {
	enabled bool
	maxHop  int
	probes  int
	timeout time.Duration
}

var tcfg traceConfig

var traceData = []byte("nsnalitrace")

// appendTrace 执行路由跟踪，把逐跳结果（含归属地）追加到 line 后返回。
func appendTrace(line, ip string) string {
	dst := net.ParseIP(ip)
	if dst == nil || dst.To4() == nil {
		return line + fmt.Sprintf("\n  Trace:\t仅支持 IPv4，跳过 %s", ip)
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return line + fmt.Sprintf("\n  Trace:\t需要 root 或 CAP_NET_RAW 权限 (%v)", err)
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	var b strings.Builder
	b.WriteString(line)
	fmt.Fprintf(&b, "\n  Trace to %s:", ip)

	for ttl := 1; ttl <= tcfg.maxHop; ttl++ {
		if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
			b.WriteString(fmt.Sprintf("\n    设置 TTL=%d 失败: %v", ttl, err))
			break
		}
		rtts := make([]string, 0, tcfg.probes)
		var hopIP net.IP
		reached := false

		for p := 0; p < tcfg.probes; p++ {
			seq := ttl*256 + p
			wm := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Body: &icmp.Echo{ID: id, Seq: seq, Data: traceData},
			}
			wb, err := wm.Marshal(nil)
			if err != nil {
				b.WriteString(fmt.Sprintf("\n    构造探测包失败: %v", err))
				return b.String()
			}
			start := time.Now()
			if _, err := conn.WriteTo(wb, &net.IPAddr{IP: dst}); err != nil {
				b.WriteString(fmt.Sprintf("\n    发送探测包失败: %v", err))
				return b.String()
			}
			conn.SetReadDeadline(start.Add(tcfg.timeout))
			rb := make([]byte, 1500)
			n, peer, err := conn.ReadFrom(rb)
			if err != nil {
				rtts = append(rtts, "*ms")
				continue
			}
			rtt := time.Since(start)
			rm, err := icmp.ParseMessage(1, rb[:n])
			if err != nil {
				rtts = append(rtts, "*ms")
				continue
			}
			switch body := rm.Body.(type) {
			case *icmp.TimeExceeded:
				// 只认自己发的包：从 payload 的原始 IP 头里取 Echo ID/Seq
				gotID, gotSeq := echoIDSeq(body.Data)
				if gotID != id || gotSeq != seq {
					rtts = append(rtts, "*ms")
					continue
				}
				hopIP = peerIP(peer)
				rtts = append(rtts, fmt.Sprintf("%.1fms", ms(rtt)))
			case *icmp.Echo:
				if body.ID != id || body.Seq != seq {
					rtts = append(rtts, "*ms")
					continue
				}
				hopIP = peerIP(peer)
				rtts = append(rtts, fmt.Sprintf("%.1fms", ms(rtt)))
				reached = true
			default:
				rtts = append(rtts, "*ms")
			}
		}

		if hopIP == nil {
			fmt.Fprintf(&b, "\n    %2d  %s", ttl, strings.Join(rtts, "  "))
			continue
		}
		fmt.Fprintf(&b, "\n    %2d  %-15s [%s]  %s", ttl, hopIP.String(), region(hopIP.String()), strings.Join(rtts, "  "))
		if reached {
			break
		}
	}
	return b.String()
}

func peerIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	return nil
}

// echoIDSeq 从 ICMP Time Exceeded 携带的原始 IP 数据报中提取 Echo 的 ID 和 Seq。
// 原始报文布局：IP 头（IHL*4 字节） + ICMP Echo 头（ID 2 字节 + Seq 2 字节）。
func echoIDSeq(data []byte) (int, int) {
	if len(data) < 28 {
		return -1, -1
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+8 {
		return -1, -1
	}
	return int(data[ihl+4])<<8 | int(data[ihl+5]), int(data[ihl+6])<<8 | int(data[ihl+7])
}
