// DNS connection pool — چند connection همزمان به nameserver
// از ساختن connection جدید برای هر query جلوگیری میکنه
package dnscache

import (
	"net"
	"sync"
	"time"
)

// udpPool یه pool از UDP connections به nameserver
type udpPool struct {
	addr    string
	mu      sync.Mutex
	conns   []net.Conn
	maxSize int
}

func newUDPPool(addr string, size int) *udpPool {
	if size <= 0 {
		size = 4
	}
	return &udpPool{addr: addr, maxSize: size}
}

func (p *udpPool) get() (net.Conn, error) {
	p.mu.Lock()
	if len(p.conns) > 0 {
		conn := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		p.mu.Unlock()
		return conn, nil
	}
	p.mu.Unlock()
	return net.DialTimeout("udp", p.addr, 5*time.Second)
}

func (p *udpPool) put(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns) >= p.maxSize {
		conn.Close()
		return
	}
	// reset deadline
	conn.SetDeadline(time.Time{})
	p.conns = append(p.conns, conn)
}

func (p *udpPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}
