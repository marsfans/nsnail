package main

// mtr：ping + trace 的融合版。持续对每一跳发包，累积统计丢包率与延迟波动，
// 复用 trace.go 的 ICMP 探测、ID/Seq 匹配和 main.go 的归属地查询。
// Ctrl+C 停止并输出最终统计；-mtr-rounds 可限定轮数（便于脚本/测试）。

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type mtrConfig struct {
	enabled bool
	maxHop  int
	count   int
	rounds  int
	timeout time.Duration
}

var mcfg mtrConfig

type mtrStat struct {
	sent    int
	recv    int
	sum     float64
	sumsq   float64
	min     float64
	max     float64
	seen    map[string]int
	reached bool // 该跳是否为目标
}

// runMTR 对一个 IPv4 目标执行持续路由探测。
func runMTR(target string) {
	dst := net.ParseIP(target)
	if dst == nil || dst.To4() == nil {
		fmt.Printf("mtr: 仅支持 IPv4 目标: %s\n", target)
		return
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("mtr: 需要 root 或 CAP_NET_RAW 权限 (%v)\n", err)
		return
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	stats := make([]*mtrStat, mcfg.maxHop)
	for i := range stats {
		stats[i] = &mtrStat{min: math.MaxFloat64, seen: map[string]int{}}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	fmt.Printf("mtr: %s, %d hops max, %d probes per hop, timeout %v\n", target, mcfg.maxHop, mcfg.count, mcfg.timeout)
	fmt.Println("(Ctrl+C 停止并输出统计)")

	targetHop := mcfg.maxHop
	for round := 1; ; round++ {
		for ttl := 1; ttl <= targetHop; ttl++ {
			st := stats[ttl-1]
			ip, rtts, reached := mtrProbeHop(conn, id, dst, ttl, mcfg.count, mcfg.timeout)
			st.sent += mcfg.count
			st.recv += len(rtts)
			for _, r := range rtts {
				st.sum += r
				st.sumsq += r * r
				if r < st.min {
					st.min = r
				}
				if r > st.max {
					st.max = r
				}
			}
			if ip != "" {
				st.seen[ip]++
			}
			if reached {
				targetHop = ttl
				st.reached = true
			}
		}
		printMTR(stats, targetHop, round, target)
		if mcfg.rounds > 0 && round >= mcfg.rounds {
			break
		}
		select {
		case <-stop:
			fmt.Println("\n--- 最终统计 ---")
			printMTR(stats, targetHop, round, target)
			return
		case <-time.After(time.Second):
		}
	}
	fmt.Println("\n--- 最终统计 ---")
	printMTR(stats, targetHop, mcfg.rounds, target)
}

// mtrProbeHop 对单跳发 count 个包并收集响应，返回该跳 IP、RTT 列表和是否到达目标。
func mtrProbeHop(conn *icmp.PacketConn, id int, dst net.IP, ttl, count int, timeout time.Duration) (string, []float64, bool) {
	if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
		return "", nil, false
	}
	seqs := make([]int, count)
	sendAt := make(map[int]time.Time, count)
	for p := 0; p < count; p++ {
		seq := ttl*256 + p
		seqs[p] = seq
		wm := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: traceData}}
		wb, err := wm.Marshal(nil)
		if err != nil {
			continue
		}
		sendAt[seq] = time.Now()
		conn.WriteTo(wb, &net.IPAddr{IP: dst})
	}
	valid := map[int]bool{}
	for _, s := range seqs {
		valid[s] = true
	}
	seen := map[int]bool{}
	rtts := []float64{}
	ip := ""
	reached := false
	deadline := time.Now().Add(timeout)
	for len(seen) < count {
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		conn.SetReadDeadline(deadline)
		rb := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			break
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}
		var gotID, gotSeq int
		var isReply bool
		switch body := rm.Body.(type) {
		case *icmp.TimeExceeded:
			gotID, gotSeq = echoIDSeq(body.Data)
		case *icmp.Echo:
			gotID, gotSeq, isReply = body.ID, body.Seq, true
		default:
			continue
		}
		if gotID != id || !valid[gotSeq] || seen[gotSeq] {
			continue
		}
		seen[gotSeq] = true
		if t, ok := sendAt[gotSeq]; ok {
			rtts = append(rtts, float64(time.Since(t).Microseconds())/1000)
		}
		if ip == "" && peerIP(peer) != nil {
			ip = peerIP(peer).String()
		}
		if isReply {
			reached = true
		}
	}
	return ip, rtts, reached
}

func printMTR(stats []*mtrStat, targetHop, round int, target string) {
	fmt.Printf("\nROUND %d  target: %s\n", round, target)
	fmt.Printf(" %-3s %-16s %-42s %7s %8s %8s %8s %8s\n", "Hop", "IP", "Region", "Loss%", "Avg", "Min", "Max", "StDev")
	for i := 0; i < targetHop; i++ {
		st := stats[i]
		ip := dominantIP(st.seen)
		reg := ""
		if ip != "" {
			reg = region(ip)
		}
		loss := 100.0
		avg, mn, mx, sd := 0.0, 0.0, 0.0, 0.0
		if st.sent > 0 {
			loss = float64(st.sent-st.recv) / float64(st.sent) * 100
		}
		if st.recv > 0 {
			avg = st.sum / float64(st.recv)
			mn = st.min
			mx = st.max
			variance := st.sumsq/float64(st.recv) - avg*avg
			if variance > 0 {
				sd = math.Sqrt(variance)
			}
		}
		lossStr := fmt.Sprintf("%.1f%%", loss)
		avgStr, minStr, maxStr, sdStr := "-", "-", "-", "-"
		if st.recv > 0 {
			avgStr = fmt.Sprintf("%.1fms", avg)
			minStr = fmt.Sprintf("%.1fms", mn)
			maxStr = fmt.Sprintf("%.1fms", mx)
			sdStr = fmt.Sprintf("%.1fms", sd)
		}
		if ip == "" {
			ip = "???"
		}
		fmt.Printf(" %-3d %-16s %-42s %7s %8s %8s %8s %8s\n", i+1, ip, reg, lossStr, avgStr, minStr, maxStr, sdStr)
	}
	fmt.Println()
}

func dominantIP(seen map[string]int) string {
	if len(seen) == 0 {
		return ""
	}
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range seen {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	return strings.TrimSpace(list[0].k)
}
