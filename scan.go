package main

// 端口扫描：并发 TCP connect 扫描，支持单 IP、CIDR/IP 段、ASN 三种目标。
// 复用 tcping 的 net.DialTimeout 思路，用 worker pool 控制并发。
// 目标写法：
//   单 IP:        1.1.1.1
//   CIDR:         192.168.1.0/24
//   IP 范围:      192.168.1.1-192.168.1.10
//   简写范围:     192.168.1.1-10
//   ASN:          AS15169 / 15169（查出宣告网段后按代表地址扫描）

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type scanConfig struct {
	enabled     bool
	ports       string
	concurrency int
	timeout     time.Duration
	maxHosts    int
	showClosed  bool
}

var scfg scanConfig

type scanResult struct {
	host string
	port int
}

// parsePorts 解析端口规格：逗号分隔的端口/范围，如 "22,80,443,8000-8080"。
func parsePorts(spec string) ([]int, error) {
	set := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("无效端口范围: %s", part)
			}
			for p := lo; p <= hi; p++ {
				set[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("无效端口: %s", part)
			}
			set[p] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// expandTargets 解析目标规格，展开成主机列表。
func expandTargets(spec string) ([]string, string, error) {
	spec = strings.TrimSpace(spec)
	// ASN: AS15169 或纯数字
	asn := ""
	if strings.HasPrefix(strings.ToUpper(spec), "AS") {
		asn = spec[2:]
	} else if _, err := strconv.Atoi(spec); err == nil {
		asn = spec
	}
	if asn != "" {
		hosts, prefixes, err := hostsFromASN(asn, scfg.maxHosts)
		return hosts, fmt.Sprintf("ASN AS%s (%d 网段)", asn, prefixes), err
	}
	// CIDR
	if strings.Contains(spec, "/") {
		hosts, err := hostsFromCIDR(spec, scfg.maxHosts)
		return hosts, "CIDR " + spec, err
	}
	// IP 范围: a.b.c.d-a.b.c.e 或 a.b.c.d-start-end
	if strings.Contains(spec, "-") {
		hosts, err := hostsFromRange(spec, scfg.maxHosts)
		return hosts, "范围 " + spec, err
	}
	// 单 IP
	if net.ParseIP(spec) != nil {
		return []string{spec}, "主机 " + spec, nil
	}
	return nil, "", fmt.Errorf("无法识别目标: %s（支持 IP / CIDR / 范围 / ASN）", spec)
}

func hostsFromCIDR(cidr string, max int) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	_ = ip
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("仅支持 IPv4 CIDR: %s", cidr)
	}
	total := 1 << uint(bits-ones) // 主机数含网络/广播
	hostCount := total
	if total > 2 {
		hostCount = total - 2 // 去掉网络号和广播地址
	}
	if hostCount > max {
		hostCount = max
	}
	base := network.IP.To4()
	var hosts []string
	for i := 1; i <= hostCount; i++ { // 从网络号+1 开始
		n := uint32(i)
		ip4 := net.IPv4(base[0], base[1], base[2], base[3]).To4()
		v := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		v += n
		if total > 2 && i >= total-1 { // 跳过广播
			break
		}
		hosts = append(hosts, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String())
	}
	return hosts, nil
}

func hostsFromRange(spec string, max int) ([]string, error) {
	parts := strings.SplitN(spec, "-", 2)
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil || startIP.To4() == nil {
		return nil, fmt.Errorf("无效起始 IP: %s", parts[0])
	}
	endPart := strings.TrimSpace(parts[1])
	var endIP net.IP
	if strings.Contains(endPart, ".") {
		endIP = net.ParseIP(endPart)
	} else {
		// 简写: 192.168.1.1-10 -> 同网段
		n, err := strconv.Atoi(endPart)
		if err != nil {
			return nil, fmt.Errorf("无效结束 IP: %s", endPart)
		}
		b := startIP.To4()
		endIP = net.IPv4(b[0], b[1], b[2], byte(n))
	}
	if endIP == nil || endIP.To4() == nil {
		return nil, fmt.Errorf("无效结束 IP: %s", endPart)
	}
	s := ipToUint32(startIP)
	e := ipToUint32(endIP)
	if e < s {
		return nil, fmt.Errorf("结束 IP 小于起始 IP")
	}
	count := int(e - s + 1)
	if count > max {
		count = max
	}
	var hosts []string
	for i := 0; i < count; i++ {
		hosts = append(hosts, uint32ToIP(s+uint32(i)).String())
	}
	return hosts, nil
}

func ipToUint32(ip net.IP) uint32 {
	v := ip.To4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// hostsFromASN 通过 RIPEstat 查 AS 宣告的 IPv4 网段，每个网段取网络地址+1 作为代表主机。
func hostsFromASN(asn string, max int) ([]string, int, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("RIPEstat 请求失败: %w", err)
	}
	defer resp.Body.Close()
	var data struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, 0, fmt.Errorf("解析 RIPEstat 响应失败: %w", err)
	}
	var hosts []string
	v4Count := 0
	for _, p := range data.Data.Prefixes {
		if !strings.Contains(p.Prefix, ":") { // 仅 IPv4
			v4Count++
			ip, network, err := net.ParseCIDR(p.Prefix)
			if err != nil {
				continue
			}
			_ = ip
			base := network.IP.To4()
			if base == nil {
				continue
			}
			// 取网络地址+1 作为代表主机
			host := uint32ToIP(ipToUint32(base) + 1).String()
			hosts = append(hosts, host)
			if len(hosts) >= max {
				break
			}
		}
	}
	if len(hosts) == 0 {
		return nil, v4Count, fmt.Errorf("AS%s 未找到可扫描的 IPv4 网段", asn)
	}
	return hosts, v4Count, nil
}

// runScan 执行扫描并返回格式化结果文本。
func runScan(target string) string {
	ports, err := parsePorts(scfg.ports)
	if err != nil {
		return "扫描参数错误: " + err.Error()
	}
	hosts, desc, err := expandTargets(target)
	if err != nil {
		return "目标解析错误: " + err.Error()
	}
	if len(hosts) == 0 {
		return "未展开出任何主机"
	}
	fmt.Printf("扫描目标: %s | 主机 %d | 端口 %d | 并发 %d\n", desc, len(hosts), len(ports), scfg.concurrency)

	jobs := make(chan scanResult, len(hosts)*len(ports))
	var wg sync.WaitGroup
	var scanned, opened int64
	openResults := make(chan scanResult, len(hosts)*len(ports))

	worker := func() {
		defer wg.Done()
		for job := range jobs {
			atomic.AddInt64(&scanned, 1)
			addr := net.JoinHostPort(job.host, strconv.Itoa(job.port))
			conn, err := net.DialTimeout("tcp", addr, scfg.timeout)
			if err == nil {
				conn.Close()
				atomic.AddInt64(&opened, 1)
				openResults <- job
			}
		}
	}
	workers := scfg.concurrency
	if workers < 1 {
		workers = 100
	}
	if workers > len(hosts)*len(ports) {
		workers = len(hosts)*len(ports)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}
	for _, h := range hosts {
		for _, p := range ports {
			jobs <- scanResult{h, p}
		}
	}
	close(jobs)
	wg.Wait()
	close(openResults)

	var b strings.Builder
	fmt.Fprintf(&b, "\n扫描完成: %d 主机 × %d 端口 = %d 次连接, 开放 %d\n", len(hosts), len(ports), atomic.LoadInt64(&scanned), atomic.LoadInt64(&opened))
	// 按主机聚合开放端口
	byHost := map[string][]int{}
	for r := range openResults {
		byHost[r.host] = append(byHost[r.host], r.port)
	}
	hostList := make([]string, 0, len(byHost))
	for h := range byHost {
		hostList = append(hostList, h)
	}
	sort.Strings(hostList)
	for _, h := range hostList {
		ps := byHost[h]
		sort.Ints(ps)
		portsStr := make([]string, len(ps))
		for i, p := range ps {
			portsStr[i] = strconv.Itoa(p)
		}
		fmt.Fprintf(&b, "  %s [%s]: %s\n", h, region(h), strings.Join(portsStr, ", "))
	}
	if len(byHost) == 0 {
		fmt.Fprintln(&b, "  (未发现开放端口)")
	}
	return b.String()
}
