package main

// 本文件给 nsnali 增加 ICMP 探测能力：
//   1) 优先使用 go-ping（纯 Go，拿到结构化统计；Linux 上走非特权 ping socket，无需 root）
//   2) 若内核禁用 ping socket（如 /proc/sys/net/ipv4/ping_group_range = 1 0）则自动降级，
//      调用系统 ping 命令并解析统计行，保证在受限环境里也能用。

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-ping/ping"
)

type pingConfig struct {
	enabled bool
	count   int
	timeout time.Duration
}

var pcfg pingConfig

// PingResult 一次探测的汇总结果
type PingResult struct {
	Sent, Recv int
	Loss       float64 // 百分比
	Min, Avg   time.Duration
	Max        time.Duration
	Via        string // "icmp" 或 "cmd"
	Raw        string // 降级模式下解析失败时保留原始输出
}

func (r PingResult) String() string {
	if r.Recv == 0 && r.Sent > 0 {
		return fmt.Sprintf("丢包 100%% (%d/%d)", r.Sent-r.Recv, r.Sent)
	}
	if r.Raw != "" {
		return r.Raw
	}
	return fmt.Sprintf("延迟 min/avg/max = %.1f/%.1f/%.1f ms, 丢包 %.0f%%",
		ms(r.Min), ms(r.Avg), ms(r.Max), r.Loss)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// pingIP 先试纯 Go ICMP，失败则降级到系统 ping
func pingIP(ip string) (PingResult, error) {
	if r, err := pingICMP(ip); err == nil {
		return r, nil
	}
	return pingCommand(ip)
}

// pingICMP 用 go-ping 发包，无需 root（依赖内核允许非特权 ping socket）
func pingICMP(ip string) (PingResult, error) {
	p, err := ping.NewPinger(ip)
	if err != nil {
		return PingResult{}, err
	}
	p.Count = pcfg.count
	p.Timeout = pcfg.timeout
	p.SetPrivileged(false) // Linux: udp4 ping socket；同时兼容自动检测 IPv6
	if err := p.Run(); err != nil {
		return PingResult{}, err
	}
	s := p.Statistics()
	return PingResult{
		Sent: s.PacketsSent, Recv: s.PacketsRecv, Loss: s.PacketLoss,
		Min: s.MinRtt, Avg: s.AvgRtt, Max: s.MaxRtt, Via: "icmp",
	}, nil
}

// pingCommand 降级方案：调用系统 ping，解析统计输出
func pingCommand(ip string) (PingResult, error) {
	sec := int(pcfg.timeout.Seconds())
	if sec < 1 {
		sec = 1
	}
	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"-n", strconv.Itoa(pcfg.count), "-w", strconv.Itoa(sec * 1000), ip}
	default: // linux / darwin / bsd
		args = []string{"-c", strconv.Itoa(pcfg.count), "-W", strconv.Itoa(sec * 1000), ip}
	}
	// 硬超时：系统 ping 的 -W 只控制单次等待，黑洞路由时可能挂很久，
	// 这里用 context 强制兜底，保证最多 count*timeout+2s 后返回。
	deadline := pcfg.timeout*time.Duration(pcfg.count) + 2*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run() // 100% 丢包时退出码非 0，不算错误
	raw := strings.TrimSpace(out.String())
	if ctx.Err() != nil {
		return PingResult{}, fmt.Errorf("系统 ping 超时 (%.0fs)", deadline.Seconds())
	}
	r := parsePingOutput(raw)
	r.Via = "cmd"
	if r.Sent == 0 && err != nil {
		if raw != "" {
			return PingResult{}, fmt.Errorf("系统 ping 执行失败: %v (%s)", err, raw)
		}
		return PingResult{}, fmt.Errorf("系统 ping 执行失败: %v", err)
	}
	return r, nil
}

var (
	reLoss   = regexp.MustCompile(`([\d.]+)\s*%\s*(?:packet\s*loss|丢包|丢失|封包遺失)`)
	reRtt    = regexp.MustCompile(`(?:rtt|round-trip)[^\n]*?=\s*([\d.]+)/([\d.]+)/([\d.]+)`)
	reSent   = regexp.MustCompile(`(\d+)\s*(?:packets?\s*)?(?:transmitted|已发送|个数据包已传输)`)
	reRecv   = regexp.MustCompile(`(\d+)\s*(?:packets?\s*)?(?:received|已接收|个接收|接收)`)
	reWinMin = regexp.MustCompile(`最短\s*=\s*([\d.]+)\s*ms`)
	reWinMax = regexp.MustCompile(`最长\s*=\s*([\d.]+)\s*ms`)
	reWinAvg = regexp.MustCompile(`平均\s*=\s*([\d.]+)\s*ms`)
)

func parsePingOutput(raw string) PingResult {
	r := PingResult{}
	if m := reSent.FindStringSubmatch(raw); len(m) == 2 {
		r.Sent, _ = strconv.Atoi(m[1])
	}
	if m := reRecv.FindStringSubmatch(raw); len(m) == 2 {
		r.Recv, _ = strconv.Atoi(m[1])
	}
	if m := reLoss.FindStringSubmatch(raw); len(m) == 2 {
		r.Loss, _ = strconv.ParseFloat(m[1], 64)
	} else if r.Sent > 0 {
		r.Loss = float64(r.Sent-r.Recv) / float64(r.Sent) * 100
	}
	if m := reRtt.FindStringSubmatch(raw); len(m) == 4 {
		r.Min = parseMs(m[1])
		r.Avg = parseMs(m[2])
		r.Max = parseMs(m[3])
	} else {
		// Windows 中文输出：最短/最长/平均 分行显示
		if m := reWinMin.FindStringSubmatch(raw); len(m) == 2 {
			r.Min = parseMs(m[1])
		}
		if m := reWinMax.FindStringSubmatch(raw); len(m) == 2 {
			r.Max = parseMs(m[1])
		}
		if m := reWinAvg.FindStringSubmatch(raw); len(m) == 2 {
			r.Avg = parseMs(m[1])
		}
	}
	if r.Sent == 0 {
		// 解析不出来就原样展示最后一行统计，保证信息不丢
		lines := strings.Split(raw, "\n")
		if len(lines) > 0 {
			r.Raw = strings.TrimSpace(lines[len(lines)-1])
		}
	}
	return r
}

func parseMs(s string) time.Duration {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return time.Duration(f * float64(time.Millisecond))
}

// appendPing 给一行输出追加 ping 结果（供 main.go 调用）
func appendPing(line, ip string) string {
	r, err := pingIP(ip)
	if err != nil {
		return line + fmt.Sprintf("\n  Ping:\t失败 - %v", err)
	}
	return line + fmt.Sprintf("\n  Ping:\t%s [%s]", r.String(), r.Via)
}
