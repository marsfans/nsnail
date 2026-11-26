package main

// HTTPS 证书检查：用标准库 crypto/tls 连接目标，获取证书链信息。
// 检查颁发者、主题、有效期、剩余天数、TLS 版本、SAN（域名）。
// 无需外部依赖，但目标需可达且端口开放（默认 443）。

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type certConfig struct {
	enabled bool
	port    int
	timeout time.Duration
	insecure bool
}

var certcfg certConfig

// certCheck 对 host:port 做 TLS 握手，返回证书摘要多行文本。
func certCheck(host string) string {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", certcfg.port))
	dialer := &net.Dialer{Timeout: certcfg.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: certcfg.insecure,
	})
	if err != nil {
		return fmt.Sprintf("  Cert:\t连接失败 (%s): %v", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "  Cert:\t未获取到证书"
	}
	cert := state.PeerCertificates[0]

	var b strings.Builder
	version := tlsVersionName(state.Version)
	remaining := int(time.Until(cert.NotAfter).Hours() / 24)
	status := "有效"
	if remaining < 0 {
		status = "已过期"
	} else if remaining <= 30 {
		status = "即将过期"
	}

	fmt.Fprintf(&b, "  Cert:\t%s", addr)
	fmt.Fprintf(&b, "\n    TLS:        %s", version)
	fmt.Fprintf(&b, "\n    颁发者:     %s", cert.Issuer.String())
	fmt.Fprintf(&b, "\n    主题:       %s", cert.Subject.String())
	fmt.Fprintf(&b, "\n    有效期:     %s ~ %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(&b, "\n    剩余:       %d 天 (%s)", remaining, status)
	if len(cert.DNSNames) > 0 {
		sans := cert.DNSNames
		if len(sans) > 3 {
			sans = append(sans[:3], fmt.Sprintf("...共%d个", len(cert.DNSNames)))
		}
		fmt.Fprintf(&b, "\n    SAN:        %s", strings.Join(sans, ", "))
	}
	if len(state.PeerCertificates) > 1 {
		fmt.Fprintf(&b, "\n    证书链:     %d 级", len(state.PeerCertificates))
	}
	// 握手本身已完成证书链校验（InsecureSkipVerify=false 时），直接采用其结果，
	// 避免二次 Verify 因根证书池路径差异产生误报。
	if certcfg.insecure {
		fmt.Fprintf(&b, "\n    校验:       跳过 (-cert-insecure)")
	} else {
		fmt.Fprintf(&b, "\n    校验:       通过 (TLS 握手已验证)")
	}
	return b.String()
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

// appendCert 把证书检查结果追加到 line 后返回。
func appendCert(line, host string) string {
	return line + "\n" + certCheck(host)
}
