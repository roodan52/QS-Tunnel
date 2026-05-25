// Package dnscache — DNS resolver با cache و DoH support
//
// ویژگی‌ها:
//   - cache با TTL (پیش‌فرض ۵ دقیقه)
//   - Plain DNS (UDP/TCP به nameserver)
//   - DoH — DNS over HTTPS (cloudflare, google, یا custom)
//   - concurrent-safe با sync.Map
package dnscache

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config تنظیمات DNS
type Config struct {
	// Mode: "plain" یا "doh"
	Mode string `json:"mode"`

	// Plain DNS
	Nameserver string `json:"nameserver"` // e.g. "8.8.8.8:53"

	// DoH
	DoHURL string `json:"doh_url"` // e.g. "https://cloudflare-dns.com/dns-query"

	// Cache
	TTL         int  `json:"ttl_sec"`          // پیش‌فرض 300
	NegativeTTL int  `json:"negative_ttl_sec"` // TTL برای NXDOMAIN (پیش‌فرض 30)
	MaxEntries  int  `json:"max_entries"`       // حداکثر entry در cache (پیش‌فرض 10000)
	Enable      bool `json:"enable"`            // false = bypass، از net.DefaultResolver
}

func DefaultConfig() Config {
	return Config{
		Mode:        "plain",
		Nameserver:  "8.8.8.8:53",
		DoHURL:      "https://cloudflare-dns.com/dns-query",
		TTL:         300,
		NegativeTTL: 30,
		MaxEntries:  10000,
		Enable:      true,
	}
}

// entry یه record کشده‌شده
type entry struct {
	ips     []net.IP
	expiry  time.Time
	isError bool // NXDOMAIN یا خطا
}

func (e *entry) alive() bool {
	return time.Now().Before(e.expiry)
}

// Resolver یه DNS resolver با cache
type Resolver struct {
	cfg      Config
	cache    sync.Map          // string → *entry
	mu       sync.Mutex
	inflight map[string]*call  // singleflight
	client   *http.Client      // برای DoH
	pool     *udpPool          // connection pool برای plain DNS
	total    uint64
	hits     uint64
	misses   uint64
}

// call برای singleflight
type call struct {
	wg  sync.WaitGroup
	val []net.IP
	err error
}

func New(cfg Config) *Resolver {
	r := &Resolver{
		cfg:      cfg,
		inflight: make(map[string]*call),
	}
	if cfg.Mode == "doh" {
		r.client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				MaxIdleConns:    10,
			},
		}
	} else {
		// connection pool برای plain DNS — 4 connection همزمان
		ns := cfg.Nameserver
		if ns == "" { ns = "8.8.8.8:53" }
		if len(ns) > 0 && ns[len(ns)-1] != ':' && !containsPort(ns) {
			ns += ":53"
		}
		r.pool = newUDPPool(ns, 4)
	}
	return r
}

func containsPort(s string) bool {
	for i := len(s)-1; i >= 0; i-- {
		if s[i] == ':' { return true }
		if s[i] == ']' { return false }
	}
	return false
}

// LookupHost یه hostname رو resolve میکنه (با cache)
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	// IP literal — resolve نمیخواد
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	// بررسی cache
	if v, ok := r.cache.Load(host); ok {
		e := v.(*entry)
		if e.alive() {
			r.hits++
			if e.isError {
				return nil, fmt.Errorf("NXDOMAIN: %s", host)
			}
			return e.ips, nil
		}
		r.cache.Delete(host)
	}
	r.misses++

	// singleflight — فقط یه goroutine lookup میکنه
	r.mu.Lock()
	if c, ok := r.inflight[host]; ok {
		r.mu.Unlock()
		c.wg.Wait()
		if c.err != nil {
			return nil, c.err
		}
		return c.val, nil
	}
	c := &call{}
	c.wg.Add(1)
	r.inflight[host] = c
	r.mu.Unlock()

	// resolve
	var ips []net.IP
	var err error
	if !r.cfg.Enable {
		// bypass — از Go default resolver
		addrs, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			err = e
		} else {
			for _, a := range addrs {
				if ip4 := a.IP.To4(); ip4 != nil {
					ips = append(ips, ip4)
				}
			}
			if len(ips) == 0 {
				for _, a := range addrs {
					ips = append(ips, a.IP)
				}
			}
		}
	} else {
		switch r.cfg.Mode {
		case "doh":
			ips, err = r.lookupDoH(ctx, host)
		default:
			ips, err = r.lookupPlain(ctx, host)
		}
	}

	// ذخیره در cache
	ttl := time.Duration(r.cfg.TTL) * time.Second
	if err != nil {
		ttl = time.Duration(r.cfg.NegativeTTL) * time.Second
		r.cache.Store(host, &entry{expiry: time.Now().Add(ttl), isError: true})
	} else {
		r.cache.Store(host, &entry{ips: ips, expiry: time.Now().Add(ttl)})
	}

	// singleflight resolve
	c.val = ips
	c.err = err
	c.wg.Done()

	r.mu.Lock()
	delete(r.inflight, host)
	r.mu.Unlock()

	return ips, err
}

// Dial مستقیم با cache — جایگزین net.Dial
func (r *Resolver) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS %s: %w", host, err)
	}
	// اولین IP که وصل بشه
	d := &net.Dialer{Timeout: 10 * time.Second}
	for _, ip := range ips {
		resolved := net.JoinHostPort(ip.String(), port)
		conn, err := d.DialContext(ctx, network, resolved)
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("dial %s: all IPs failed", addr)
}

// Stats آمار cache
func (r *Resolver) Stats() (total, hits, misses uint64, size int) {
	n := 0
	r.cache.Range(func(_, _ any) bool { n++; return true })
	return r.total, r.hits, r.misses, n
}

// Flush cache رو خالی میکنه
func (r *Resolver) Flush() {
	r.cache.Range(func(k, _ any) bool {
		r.cache.Delete(k)
		return true
	})
}

// ─── Plain DNS ────────────────────────────────────────────────────────────────

func (r *Resolver) lookupPlain(ctx context.Context, host string) ([]net.IP, error) {
	// از pool استفاده کن — بدون overhead ساختن connection جدید
	var conn net.Conn
	var err error
	if r.pool != nil {
		conn, err = r.pool.get()
	} else {
		ns := r.cfg.Nameserver
		if ns == "" { ns = "8.8.8.8:53" }
		if !strings.Contains(ns, ":") { ns += ":53" }
		conn, err = (&net.Dialer{}).DialContext(ctx, "udp", ns)
	}
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() {
		if r.pool != nil {
			r.pool.put(conn) // برگردون به pool
		} else {
			conn.Close()
		}
	}()

	// DNS query ساده برای A record
	query := buildDNSQuery(host, 1) // Type A
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}

	ips := parseDNSResponse(resp[:n])
	if len(ips) == 0 {
		// اگه A record نبود، AAAA هم بپرس
		query6 := buildDNSQuery(host, 28)
		ns6 := r.cfg.Nameserver
		if ns6 == "" { ns6 = "8.8.8.8:53" }
		if !strings.Contains(ns6, ":") { ns6 += ":53" }
		conn2, err := (&net.Dialer{}).DialContext(ctx, "udp", ns6)
		if err == nil {
			defer conn2.Close()
			conn2.SetDeadline(time.Now().Add(3 * time.Second))
			conn2.Write(query6)
			n6, err := conn2.Read(resp)
			if err == nil {
				ips6 := parseDNSResponse(resp[:n6])
				ips = append(ips, ips6...)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no records for %s", host)
	}
	return ips, nil
}

// buildDNSQuery یه DNS query ساده میسازه
func buildDNSQuery(host string, qtype uint16) []byte {
	buf := make([]byte, 0, 512)

	// Header
	buf = append(buf,
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: recursive
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	)

	// Question — hostname to labels
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)                    // root
	buf = append(buf, byte(qtype>>8), byte(qtype)) // QTYPE
	buf = append(buf, 0x00, 0x01)              // QCLASS IN

	return buf
}

// parseDNSResponse پاسخ DNS رو parse میکنه
func parseDNSResponse(buf []byte) []net.IP {
	if len(buf) < 12 {
		return nil
	}
	ancount := binary.BigEndian.Uint16(buf[6:8])
	if ancount == 0 {
		return nil
	}

	var ips []net.IP
	pos := 12

	// skip question section
	for pos < len(buf) {
		if buf[pos] == 0 {
			pos++
			break
		}
		if buf[pos]&0xC0 == 0xC0 {
			pos += 2
			break
		}
		pos += int(buf[pos]) + 1
	}
	pos += 4 // QTYPE + QCLASS

	// parse answers
	for i := 0; i < int(ancount) && pos < len(buf); i++ {
		// skip name (pointer یا labels)
		if buf[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for pos < len(buf) && buf[pos] != 0 {
				pos += int(buf[pos]) + 1
			}
			pos++
		}
		if pos+10 > len(buf) {
			break
		}
		rtype := binary.BigEndian.Uint16(buf[pos:])
		pos += 8 // type + class + ttl
		rdlen := int(binary.BigEndian.Uint16(buf[pos:]))
		pos += 2

		if pos+rdlen > len(buf) {
			break
		}
		if rtype == 1 && rdlen == 4 { // A
			ips = append(ips, net.IP(append([]byte{}, buf[pos:pos+4]...)))
		} else if rtype == 28 && rdlen == 16 { // AAAA
			ips = append(ips, net.IP(append([]byte{}, buf[pos:pos+16]...)))
		}
		pos += rdlen
	}
	return ips
}

// ─── DoH ─────────────────────────────────────────────────────────────────────

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
		TTL  int    `json:"TTL"`
	} `json:"Answer"`
}

func (r *Resolver) lookupDoH(ctx context.Context, host string) ([]net.IP, error) {
	url := r.cfg.DoHURL
	if url == "" {
		url = "https://cloudflare-dns.com/dns-query"
	}

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s?name=%s&type=A", url, host), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var result dohResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("DoH parse: %w", err)
	}

	var ips []net.IP
	for _, a := range result.Answer {
		if a.Type == 1 || a.Type == 28 { // A یا AAAA
			if ip := net.ParseIP(strings.TrimSpace(a.Data)); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no records for %s via DoH", host)
	}
	return ips, nil
}
