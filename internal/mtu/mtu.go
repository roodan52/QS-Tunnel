// Package mtu — کنترل MTU و fragmentation
//
// محاسبه max payload:
//   Ethernet MTU = 1500
//   IP header    = 20 bytes
//   UDP header   = 8 bytes
//   tunnel hdr   = 9 bytes
//   ─────────────────
//   max payload  = 1500 - 37 = 1463 → با margin: 1400
package mtu

// Config تنظیمات MTU
type Config struct {
	MTU          int  `json:"mtu"`           // پیش‌فرض 1500
	AutoFragment bool `json:"auto_fragment"` // تقسیم payload بزرگ
}

func DefaultConfig() Config {
	return Config{MTU: 1500, AutoFragment: true}
}

const (
	ipv4Overhead   = 20
	udpOverhead    = 8
	tunnelOverhead = 9
	obfsOverhead   = 17 // obfs header size
)

// MaxPayload حداکثر payload برای یه MTU
func MaxPayload(mtu int, isObfs bool) int {
	if mtu <= 0 { mtu = 1500 }
	overhead := ipv4Overhead + udpOverhead + tunnelOverhead
	if isObfs { overhead += obfsOverhead }
	max := mtu - overhead
	if max < 512  { max = 512 }
	if max > 1400 { max = 1400 }
	return max
}

// Fragment یه payload رو به تکه‌های کوچکتر تقسیم میکنه
func Fragment(payload []byte, maxSize int) [][]byte {
	if len(payload) <= maxSize {
		return [][]byte{payload}
	}
	var parts [][]byte
	for len(payload) > 0 {
		size := maxSize
		if size > len(payload) { size = len(payload) }
		part := make([]byte, size)
		copy(part, payload[:size])
		parts = append(parts, part)
		payload = payload[size:]
	}
	return parts
}
