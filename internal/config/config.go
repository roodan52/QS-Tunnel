// Package config — مدیریت config با اولویت‌بندی
//
// اولویت: flag > config.json > auto-detect > default
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ─── Client Config ────────────────────────────────────────────────────────────

type ClientConfig struct {
	// اتصال به سرور
	ServerAddr    string `json:"server_addr"`     // آدرس سرور تونل (IP:port)
	UploadProxy   string `json:"upload_proxy"`    // SOCKS5 آپلود (xray/v2ray/هر چیزی)
	LocalSocks    string `json:"local_socks"`     // SOCKS5 که مرورگر به اون وصل میشه
	DownloadPort  int    `json:"download_port"`   // پورت UDP دریافت دانلود
	MyPublicIP    string `json:"my_public_ip"`    // IP عمومی کلاینت (خودکار اگه خالی)

	// Transport
	TransportMode string `json:"transport_mode"`  // "udp" یا "obfs"
	ObfsKey       string `json:"obfs_key"`        // کلید obfuscation (hex 64 کاراکتر)

	// محدودیت‌ها
	MaxStreams     int    `json:"max_streams"`     // حداکثر اتصال همزمان

	// Observability
	MetricsAddr   string `json:"metrics_addr"`    // آدرس HTTP متریک‌ها
	DashboardAddr string `json:"dashboard_addr"`  // آدرس dashboard (مثلاً 0.0.0.0:8080)
	DashboardKey  string `json:"dashboard_key"`   // کلید ورود به dashboard
	Verbose       bool   `json:"verbose"`

	// 3x-ui integration (اختیاری)
	XUI XUIConfig `json:"xui"`
}

func DefaultClient() ClientConfig {
	return ClientConfig{
		UploadProxy:   "127.0.0.1:10808",
		LocalSocks:    "127.0.0.1:1080",
		DownloadPort:  8000,
		TransportMode: "udp",
		MaxStreams:     512,
		MetricsAddr:   "127.0.0.1:9091",
		DashboardAddr: "127.0.0.1:8081",
		DashboardKey:  "changeme",
		XUI:           DefaultXUI(),
	}
}

// ─── Server Config ────────────────────────────────────────────────────────────

type ServerConfig struct {
	// اتصال
	ListenAddr         string `json:"listen_addr"`          // آدرس TCP listen
	DownloadSrcPort    int    `json:"download_src_port"`    // پورت UDP برای ارسال دانلود

	// Transport
	TransportMode      string `json:"transport_mode"`       // "udp" یا "obfs"
	ObfsKey            string `json:"obfs_key"`

	// IP Spoof (فقط حالت udp)
	SpoofIP            string `json:"spoof_ip"`             // IP جعلی برای دانلود UDP
	SpoofInterface     string `json:"spoof_interface"`      // interface خروجی (مثل eth0)
	SpoofGateway       string `json:"spoof_gateway"`        // gateway (خودکار اگه خالی)

	// TCP خروجی
	OutboundBindIP     string `json:"outbound_bind_ip"`     // IP مبدا برای اتصال TCP به مقصد

	// محدودیت‌ها
	MaxClients          int   `json:"max_clients"`
	MaxStreamsPerClient  int   `json:"max_streams_per_client"`
	FlowWindowBytes     int64 `json:"flow_window_bytes"`    // پنجره flow control
	UDPWorkers          int   `json:"udp_workers"`          // تعداد worker UDP

	// Timeouts
	DialTimeoutSec      int   `json:"dial_timeout_sec"`
	IdleTimeoutSec      int   `json:"idle_timeout_sec"`

	// Observability
	MetricsAddr         string `json:"metrics_addr"`
	DashboardAddr       string `json:"dashboard_addr"` // آدرس پنل مانیتورینگ
	DashboardKey        string `json:"dashboard_key"`  // کلید ورود به dashboard
	Verbose             bool   `json:"verbose"`

	// DNS — resolve با cache (plain یا DoH)
	DNS DNSConfig `json:"dns"`

	// MTU — کنترل اندازه پکت UDP
	MTU MTUConfig `json:"mtu"`
}

func DefaultServer() ServerConfig {
	return ServerConfig{
		ListenAddr:         "0.0.0.0:9000",
		DownloadSrcPort:    9001,
		TransportMode:      "udp",
		SpoofInterface:     "eth0",
		MaxClients:         1000,
		MaxStreamsPerClient: 256,
		FlowWindowBytes:    256 * 1024,
		DialTimeoutSec:     8,
		IdleTimeoutSec:     120,
		MetricsAddr:        "127.0.0.1:9090",
		DashboardAddr:      "0.0.0.0:8080",
		DashboardKey:       "changeme",
		DNS:                DefaultDNS(),
		MTU:                DefaultMTU(),
	}
}

// ─── Auto-detect ──────────────────────────────────────────────────────────────

// DetectPublicIP IP عمومی رو از اینترنت تشخیص میده
// اگه هیچ سرویسی در timeout جواب نداد، "N/A" برمیگردونه
// (کلاینت‌هایی که به اینترنت بین‌الملل دسترسی ندارن)
func DetectPublicIP() (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	// timeout کوتاه — اگه وصل نشد سریع رد میشه
	client := &http.Client{Timeout: 2 * time.Second}
	result := make(chan string, len(services))

	for _, svc := range services {
		go func(url string) {
			resp, err := client.Get(url)
			if err != nil {
				result <- ""
				return
			}
			body := make([]byte, 64)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			ip := strings.TrimSpace(string(body[:n]))
			if net.ParseIP(ip) != nil {
				result <- ip
			} else {
				result <- ""
			}
		}(svc)
	}

	for i := 0; i < len(services); i++ {
		if ip := <-result; ip != "" {
			return ip, nil
		}
	}
	// دسترسی به اینترنت بین‌الملل نیست — N/A برمیگردونه
	return "N/A", nil
}

// DetectOutboundIP IP خروجی به سمت server رو پیدا میکنه (بدون اینترنت)
func DetectOutboundIP(serverAddr string) (string, error) {
	c, err := net.Dial("udp4", serverAddr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// DetectDefaultInterface اسم interface خروجی پیش‌فرض رو پیدا میکنه
// از /proc/net/route میخونه — مطمئن‌ترین روش روی Linux
func DetectDefaultInterface() (string, error) {
	// روش ۱: از /proc/net/route (مطمئن‌ترین)
	data, err := os.ReadFile("/proc/net/route")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			// destination=00000000 یعنی default route
			if f[1] == "00000000" && f[7] == "00000000" {
				iface := strings.TrimSpace(f[0])
				if iface != "" {
					return iface, nil
				}
			}
		}
	}

	// روش ۲: اولین interface غیر loopback با IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					return iface.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("interface خروجی پیدا نشد — دستی تنظیم کن: spoof_interface")
}

// DetectDefaultGateway gateway پیش‌فرض رو از /proc/net/route میخونه
func DetectDefaultGateway() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if f[1] == "00000000" {
			var b [4]byte
			fmt.Sscanf(f[2][6:8], "%02x", &b[0])
			fmt.Sscanf(f[2][4:6], "%02x", &b[1])
			fmt.Sscanf(f[2][2:4], "%02x", &b[2])
			fmt.Sscanf(f[2][0:2], "%02x", &b[3])
			return net.IP(b[:]).String(), nil
		}
	}
	return "", fmt.Errorf("default route پیدا نشد")
}

// ─── Load/Save ────────────────────────────────────────────────────────────────

func LoadClient(path string) (ClientConfig, error) {
	cfg := DefaultClient()
	if err := loadJSON(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func LoadServer(path string) (ServerConfig, error) {
	cfg := DefaultServer()
	if err := loadJSON(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func loadJSON(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("باز کردن %s: %w", path, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func SaveClientExample(path string) error {
	cfg := DefaultClient()
	cfg.ServerAddr = "VPS_IP:9000"
	return saveJSON(path, cfg)
}

func SaveServerExample(path string) error {
	cfg := DefaultServer()
	return saveJSON(path, cfg)
}

func saveJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ─── Apply: flag روی config override میکنه ────────────────────────────────────

func ApplyString(cfg *string, flagVal, defaultVal string) {
	if flagVal != defaultVal && flagVal != "" {
		*cfg = flagVal
	}
}

func ApplyInt(cfg *int, flagVal, defaultVal int) {
	if flagVal != defaultVal && flagVal != 0 {
		*cfg = flagVal
	}
}

func ApplyInt64(cfg *int64, flagVal, defaultVal int64) {
	if flagVal != defaultVal && flagVal != 0 {
		*cfg = flagVal
	}
}

func ApplyBool(cfg *bool, flagVal bool) {
	if flagVal {
		*cfg = true
	}
}

// ─── XUI Config ───────────────────────────────────────────────────────────────

type XUIConfig struct {
	PanelURL    string `json:"panel_url"`    // آدرس پنل 3x-ui (مثلاً http://127.0.0.1:2053)
	Username    string `json:"username"`     // نام کاربری
	Password    string `json:"password"`     // رمز عبور
	InboundPort int    `json:"inbound_port"` // پورت upload proxy (پیش‌فرض: 1111)
	SocksPort   int    `json:"socks_port"`   // پورت socks محلی (پیش‌فرض: 7070)
}

func DefaultXUI() XUIConfig {
	return XUIConfig{
		PanelURL:    "http://127.0.0.1:2053",
		Username:    "admin",
		Password:    "",
		InboundPort: 1111,
		SocksPort:   7070,
	}
}

// ─── DNS Config ───────────────────────────────────────────────────────────────

type DNSConfig struct {
	Enable      bool   `json:"enable"`           // true = استفاده از این DNS
	Mode        string `json:"mode"`             // "plain" یا "doh"
	Nameserver  string `json:"nameserver"`       // برای plain: "8.8.8.8:53"
	DoHURL      string `json:"doh_url"`          // برای doh: "https://cloudflare-dns.com/dns-query"
	TTLSec      int    `json:"ttl_sec"`          // مدت نگه‌داری در cache (ثانیه)
	NegTTLSec   int    `json:"negative_ttl_sec"` // TTL برای NXDOMAIN
	MaxEntries  int    `json:"max_entries"`      // حداکثر entry در cache
}

func DefaultDNS() DNSConfig {
	return DNSConfig{
		Enable:     true,
		Mode:       "plain",
		Nameserver: "8.8.8.8:53",
		DoHURL:     "https://cloudflare-dns.com/dns-query",
		TTLSec:     300,
		NegTTLSec:  30,
		MaxEntries: 10000,
	}
}

// ─── MTU Config ───────────────────────────────────────────────────────────────

type MTUConfig struct {
	MTU          int  `json:"mtu"`           // اندازه MTU شبکه (پیش‌فرض 1500)
	AutoFragment bool `json:"auto_fragment"` // تقسیم payload بزرگ‌تر از MTU
}

func DefaultMTU() MTUConfig {
	return MTUConfig{MTU: 1500, AutoFragment: true}
}
