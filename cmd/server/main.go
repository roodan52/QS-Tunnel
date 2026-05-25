// سرور split-tunnel
//
// معماری جدید کلاینت:
//
//	هر stream = یه TCP connection مستقل
//	Hello پیام اول هر TCP با sessionID مشترک
//	سرور sessionID‌ها رو گروه‌بندی میکنه → یه session
//	UDP دانلود به IP:port کلاینت (از Hello)
package main

import (
	"context"
	cryptoRand "crypto/rand"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	cfgpkg "github.com/Qteam-official/QS-Tunnel/internal/config"
	"github.com/Qteam-official/QS-Tunnel/internal/dashboard"
	"github.com/Qteam-official/QS-Tunnel/internal/dnscache"
	"github.com/Qteam-official/QS-Tunnel/internal/limit"
	"github.com/Qteam-official/QS-Tunnel/internal/metrics"
	"github.com/Qteam-official/QS-Tunnel/internal/mtu"
	"github.com/Qteam-official/QS-Tunnel/internal/pool"
	"github.com/Qteam-official/QS-Tunnel/internal/proto"
	"github.com/Qteam-official/QS-Tunnel/internal/sendpool"
	"github.com/Qteam-official/QS-Tunnel/internal/session"
	"github.com/Qteam-official/QS-Tunnel/internal/spoof"
	"github.com/Qteam-official/QS-Tunnel/internal/transport"
)

var (
	M       = metrics.New()
	idleDur = 2 * time.Minute

	// udpFramePool — بازاستفاده از frame buffer برای ارسال UDP
	// هر worker سرور یه pool مجزا داره → کاهش contention
	udpFramePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 2048)
			return &b
		},
	}

	// rbufPool — read buffer از dst connection
	rbufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024) // 32KB — بزرگ‌تر برای throughput
			return &b
		},
	}

	// writePool — buffer برای TCP write coalescing
	writePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 64*1024)
			return &b
		},
	}
)

// ─── session: یه کلاینت = یه sessionID ──────────────────────────────────────
// چند TCP connection (stream) از یه sessionID
// UDP دانلود همه به یه udpDst میره

type clientSession struct {
	id          [proto.SessionIDLen]byte
	udpDst      *net.UDPAddr
	sender      *sendpool.Pool
	activeConns atomic.Int64
}

// ─── sessionManager: نگه‌داری session‌ها ────────────────────────────────────

type sessionManager struct {
	sessions sync.Map // [proto.SessionIDLen]byte → *clientSession
	limit    *limit.ConnCounter
}

func newSessionManager(maxClients int) *sessionManager {
	return &sessionManager{
		limit: limit.NewConnCounter(maxClients),
	}
}

// getOrCreate یه session پیدا یا میسازه — lock-free با sync.Map
func (sm *sessionManager) getOrCreate(id [proto.SessionIDLen]byte, udpDst *net.UDPAddr, sender *sendpool.Pool) (*clientSession, bool) {
	if v, ok := sm.sessions.Load(id); ok {
		sess := v.(*clientSession)
		sess.udpDst = udpDst
		return sess, false
	}

	// جدید
	if !sm.limit.Acquire() {
		return nil, false
	}
	sess := &clientSession{id: id, udpDst: udpDst, sender: sender}
	if actual, loaded := sm.sessions.LoadOrStore(id, sess); loaded {
		sm.limit.Release()
		actual.(*clientSession).udpDst = udpDst
		return actual.(*clientSession), false
	}
	M.ActiveClients.Add(1)
	M.TotalConnections.Add(1)
	return sess, true
}

func (sm *sessionManager) remove(id [proto.SessionIDLen]byte) {
	if _, ok := sm.sessions.LoadAndDelete(id); ok {
		sm.limit.Release()
		M.ActiveClients.Add(-1)
	}
}

// ─── tcpWriter ───────────────────────────────────────────────────────────────

type tcpWriter struct {
	ch   chan tcpJob
	done chan struct{}
}

type tcpJob struct {
	streamID uint32
	msgType  byte
	payload  []byte
	errCh    chan error
}

func newTCPWriter(conn net.Conn) *tcpWriter {
	w := &tcpWriter{ch: make(chan tcpJob, 512), done: make(chan struct{})}
	go w.loop(conn)
	return w
}

func (w *tcpWriter) loop(conn net.Conn) {
	defer close(w.done)
	hdr := make([]byte, proto.TCPHdrSize)
	cw := proto.NewCoalescingWriter(conn)
	defer cw.Close()
	for job := range w.ch {
		proto.EncodeTCPHdr(hdr, job.streamID, job.msgType, len(job.payload))
		err := cw.Write(hdr, job.payload)
		if job.errCh != nil {
			if err == nil {
				err = cw.Flush()
			}
			job.errCh <- err
		}
		if err != nil {
			for job := range w.ch {
				if job.errCh != nil {
					job.errCh <- io.ErrClosedPipe
				}
			}
			return
		}
	}
}

func (w *tcpWriter) write(sid uint32, mt byte, payload []byte, sync bool) error {
	var errCh chan error
	if sync {
		errCh = make(chan error, 1)
	}
	job := tcpJob{streamID: sid, msgType: mt, payload: payload, errCh: errCh}
	select {
	case w.ch <- job:
	case <-w.done:
		return io.ErrClosedPipe
	default:
		if !sync {
			return nil
		}
		select {
		case w.ch <- job:
		case <-w.done:
			return io.ErrClosedPipe
		}
	}
	if sync {
		select {
		case err := <-errCh:
			return err
		case <-w.done:
			return io.ErrClosedPipe
		}
	}
	return nil
}

func (w *tcpWriter) close() { close(w.ch); <-w.done }

// ─── handleTCP: یه TCP connection = یه stream ────────────────────────────────

func handleTCP(
	ctx context.Context,
	conn net.Conn,
	sm *sessionManager,
	sender *sendpool.Pool,
	tcpDial func(string) (net.Conn, error),
	flowLimit int64,
	maxPayload int,
	autoFrag bool,
	log *slog.Logger,
) {
	defer conn.Close()

	// Hello
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := proto.ReadTCPFrame(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil || f.Type != proto.MsgHello {
		return
	}
	sessionID, ip, port, err := proto.DecodeHello(f.Payload)
	if err != nil {
		return
	}
	udpDst := &net.UDPAddr{IP: ip, Port: int(port)}

	// session پیدا یا بساز
	sess, isNew := sm.getOrCreate(sessionID, udpDst, sender)
	if sess == nil {
		log.Warn("session limit پر")
		return
	}
	sess.activeConns.Add(1)
	defer func() {
		remaining := sess.activeConns.Add(-1)
		if remaining == 0 && isNew {
			sm.remove(sessionID)
		}
	}()

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		tc.SetReadBuffer(128 * 1024)
		tc.SetWriteBuffer(128 * 1024)
	}

	writer := newTCPWriter(conn)
	defer writer.close()

	// اولین message باید Connect باشه
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	f, err = proto.ReadTCPFrame(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil || f.Type != proto.MsgConnect {
		return
	}

	// stream رو باز کن
	streamID := f.StreamID
	req, err := proto.DecodeConnect(f.Payload)
	if err != nil {
		writer.write(streamID, proto.MsgConnErr, nil, false)
		return
	}

	dst := req.HostPort()
	dstConn, err := tcpDial(dst)
	if err != nil {
		M.DialErrors.Add(1)
		writer.write(streamID, proto.MsgConnErr, nil, false)
		return
	}
	if tc, ok := dstConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(60 * time.Second)
		tc.SetReadBuffer(256 * 1024)
		tc.SetWriteBuffer(64 * 1024)
	}
	defer dstConn.Close()

	// ConnAck
	if err := writer.write(streamID, proto.MsgConnAck, nil, true); err != nil {
		return
	}

	M.ActiveStreams.Add(1)
	M.TotalStreams.Add(1)
	defer M.ActiveStreams.Add(-1)

	flow := session.NewFlow(flowLimit)

	// دانلود goroutine: dst → UDP → کلاینت
	dlDone := make(chan struct{})
	var dlSeq atomic.Uint32
	go func() {
		defer close(dlDone)
		// از pool برای read buffer — کاهش allocation
		rbufPtr := rbufPool.Get().(*[]byte)
		rbuf := *rbufPtr
		// cap را به maxPayload محدود کن — جلوگیری از fragment بیش از حد
		if len(rbuf) > maxPayload {
			rbuf = rbuf[:maxPayload]
		}
		defer rbufPool.Put(rbufPtr)

		dstConn.SetDeadline(time.Now().Add(idleDur))
		for {
			n, err := dstConn.Read(rbuf)
			if n > 0 {
				if !flow.Acquire(n, 8*time.Second) {
					return
				}

				// MTU fragment
				chunks := [][]byte{rbuf[:n]}
				if autoFrag && n > maxPayload {
					chunks = mtu.Fragment(rbuf[:n], maxPayload)
				}
				for i, chunk := range chunks {
					seq := dlSeq.Add(1)
					flags := byte(0)
					if i == len(chunks)-1 && err != nil {
						flags = proto.FlagLast
					}
					// encode مستقیم — یه alloc، بدون pool overhead
					fsize := proto.UDPHdrSize + len(chunk)
					data := make([]byte, fsize)
					proto.EncodeUDP(data, streamID, seq, flags, chunk)
					sess.sender.Send(sendpool.Packet{
						StreamID: streamID,
						Data:     data,
						Dst:      sess.udpDst,
					})
				}
				M.DownloadBytes.Add(uint64(n))
				M.DownloadPackets.Add(1)
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
	}()

	// آپلود: TCP پیام‌ها بخون
	for {
		f, err := proto.ReadTCPFrame(conn)
		if err != nil {
			break
		}

		switch f.Type {
		case proto.MsgData:
			M.UploadBytes.Add(uint64(len(f.Payload)))
			M.UploadPackets.Add(1)
			if _, err := dstConn.Write(f.Payload); err != nil {
				goto done
			}

		case proto.MsgFlowAck:
			n, err := proto.DecodeFlowAck(f.Payload)
			if err == nil {
				flow.Release(int(n))
				M.FlowAcksReceived.Add(1)
			}

		case proto.MsgClose:
			goto done

		case proto.MsgPing:
			writer.write(0, proto.MsgPong, nil, false)
		}
	}

done:
	flow.Close()
	dstConn.Close()
	<-dlDone

	// FlagClose به کلاینت
	frame := make([]byte, proto.UDPHdrSize)
	proto.EncodeUDP(frame, streamID, dlSeq.Add(1), proto.FlagClose, nil)
	sess.sender.Send(sendpool.Packet{
		StreamID: streamID,
		Data:     frame,
		Dst:      sess.udpDst,
	})
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	cfgFile := flag.String("config", "", "مسیر فایل config")
	genConfig := flag.Bool("gen-config", false, "ساخت config نمونه")
	genKey := flag.Bool("gen-key", false, "ساخت کلید obfs تصادفی")

	tcpListen := flag.String("listen-addr", "", "آدرس TCP listen")
	udpSrcPort := flag.Int("download-src-port", 0, "پورت UDP ارسال دانلود")
	transportMode := flag.String("transport", "", "udp یا obfs")
	obfsKey := flag.String("obfs-key", "", "کلید obfs")
	spoofIP := flag.String("spoof-ip", "", "IP جعلی برای UDP")
	spoofIface := flag.String("spoof-interface", "", "interface برای spoof")
	spoofGW := flag.String("spoof-gateway", "", "gateway برای spoof")
	bindSrc := flag.String("outbound-bind-ip", "", "IP مبدا TCP خروجی")
	maxClients := flag.Int("max-clients", 0, "حداکثر کلاینت")
	flowLimit := flag.Int64("flow-window-bytes", 0, "پنجره flow control")
	sendWorkers := flag.Int("udp-workers", 0, "تعداد worker UDP")
	dialTimeoutS := flag.Int("dial-timeout-sec", 0, "timeout اتصال به مقصد")
	metricsAddr := flag.String("metrics-addr", "", "آدرس metrics")
	dashboardAddr := flag.String("dashboard-addr", "", "آدرس dashboard (مثلاً 0.0.0.0:8080)")
	dashboardKey := flag.String("dashboard-key", "", "کلید ورود به dashboard")
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()

	if *genKey {
		key := make([]byte, 32)
		if _, err := io.ReadFull(cryptoRand.Reader, key); err != nil {
			fmt.Fprintln(os.Stderr, "gen key:", err)
			os.Exit(1)
		}
		fmt.Printf("🔑 %x\n", key)
		fmt.Printf("  \"obfs_key\": \"%x\"\n", key)
		os.Exit(0)
	}

	if *genConfig {
		path := "server.json"
		if *cfgFile != "" {
			path = *cfgFile
		}
		cfgpkg.SaveServerExample(path)
		fmt.Printf("✅ %s ساخته شد\n./server --config %s\n", path, path)
		os.Exit(0)
	}

	// بارگذاری config
	cfg := cfgpkg.DefaultServer()
	if *cfgFile != "" {
		loaded, err := cfgpkg.LoadServer(*cfgFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		cfg = loaded
	}
	d := cfgpkg.DefaultServer()
	cfgpkg.ApplyString(&cfg.ListenAddr, *tcpListen, d.ListenAddr)
	cfgpkg.ApplyInt(&cfg.DownloadSrcPort, *udpSrcPort, d.DownloadSrcPort)
	cfgpkg.ApplyString(&cfg.TransportMode, *transportMode, d.TransportMode)
	cfgpkg.ApplyString(&cfg.ObfsKey, *obfsKey, d.ObfsKey)
	cfgpkg.ApplyString(&cfg.SpoofIP, *spoofIP, d.SpoofIP)
	cfgpkg.ApplyString(&cfg.SpoofInterface, *spoofIface, d.SpoofInterface)
	cfgpkg.ApplyString(&cfg.SpoofGateway, *spoofGW, d.SpoofGateway)
	cfgpkg.ApplyString(&cfg.OutboundBindIP, *bindSrc, d.OutboundBindIP)
	cfgpkg.ApplyInt(&cfg.MaxClients, *maxClients, d.MaxClients)
	cfgpkg.ApplyInt64(&cfg.FlowWindowBytes, *flowLimit, d.FlowWindowBytes)
	cfgpkg.ApplyInt(&cfg.UDPWorkers, *sendWorkers, d.UDPWorkers)
	cfgpkg.ApplyInt(&cfg.DialTimeoutSec, *dialTimeoutS, d.DialTimeoutSec)
	cfgpkg.ApplyString(&cfg.MetricsAddr, *metricsAddr, d.MetricsAddr)
	cfgpkg.ApplyString(&cfg.DashboardAddr, *dashboardAddr, d.DashboardAddr)
	cfgpkg.ApplyString(&cfg.DashboardKey, *dashboardKey, d.DashboardKey)
	cfgpkg.ApplyBool(&cfg.Verbose, *verbose)

	log := makeLogger(cfg.Verbose)
	log.Info("📋 config", "listen", cfg.ListenAddr, "udp_port", cfg.DownloadSrcPort,
		"transport", cfg.TransportMode, "max_clients", cfg.MaxClients)

	go func() {
		if err := M.StartHTTPServer(cfg.MetricsAddr); err != nil {
			log.Warn("metrics", "err", err)
		}
	}()

	dialTimeout := time.Duration(cfg.DialTimeoutSec) * time.Second

	// ── DNS resolver با cache ────────────────────────────────────────────────
	dnsResolver := dnscache.New(dnscache.Config{
		Enable:      cfg.DNS.Enable,
		Mode:        cfg.DNS.Mode,
		Nameserver:  cfg.DNS.Nameserver,
		DoHURL:      cfg.DNS.DoHURL,
		TTL:         cfg.DNS.TTLSec,
		NegativeTTL: cfg.DNS.NegTTLSec,
		MaxEntries:  cfg.DNS.MaxEntries,
	})
	log.Info("🌐 DNS",
		"mode", cfg.DNS.Mode,
		"server", cfg.DNS.Nameserver,
		"ttl", cfg.DNS.TTLSec,
		"cache", cfg.DNS.Enable,
	)

	// ── MTU ─────────────────────────────────────────────────────────────────
	isObfsMode := cfg.TransportMode == "obfs"
	maxPayload := mtu.MaxPayload(cfg.MTU.MTU, isObfsMode)
	log.Info("📦 MTU",
		"mtu", cfg.MTU.MTU,
		"max_payload", maxPayload,
		"auto_fragment", cfg.MTU.AutoFragment,
	)

	// TCP dialer با DNS cache
	tcpDial := makeTCPDialerWithDNS(cfg.OutboundBindIP, dialTimeout, dnsResolver)

	// ── Dashboard ─────────────────────────────────────────────────────────────
	if cfg.DashboardAddr != "" {
		key := cfg.DashboardKey
		if key == "" || key == "changeme" {
			key = "admin"
			log.Warn("⚠ dashboard_key تنظیم نشده — حتماً در server.json عوضش کن!")
		}
		dash := dashboard.New(cfg.DashboardAddr, key, *cfgFile, func() dashboard.Stats {
			s := M.Snapshot()
			return dashboard.Stats{
				ActiveStreams:   s.ActiveStreams,
				ActiveClients:   s.ActiveClients,
				TotalStreams:    s.TotalStreams,
				UploadMB:        float64(s.UploadBytes) / 1e6,
				DownloadMB:      float64(s.DownloadBytes) / 1e6,
				UploadSpeedKB:   float64(s.UploadBytes) / 1e3,
				DownloadSpeedKB: float64(s.DownloadBytes) / 1e3,
				Reconnects:      s.Reconnects,
				DialErrors:      s.DialErrors,
			}
		}, dnsResolver.Flush)
		go func() {
			log.Info("🖥  dashboard", "addr", "http://"+cfg.DashboardAddr)
			if err := dash.Start(); err != nil {
				log.Warn("dashboard", "err", err)
			}
		}()
	}

	// ── Transport ────────────────────────────────────────────────────────────
	var resolvedGW, resolvedIface string
	if cfg.SpoofIP != "" {
		resolvedGW = cfg.SpoofGateway
		if resolvedGW == "" {
			gw, err := spoof.DefaultGateway()
			if err != nil {
				log.Error("gateway detect", "err", err)
				os.Exit(1)
			}
			resolvedGW = gw
		}
		resolvedIface = cfg.SpoofInterface
		if resolvedIface == "" {
			iface, err := cfgpkg.DetectDefaultInterface()
			if err != nil {
				log.Error("interface detect", "err", err)
				// نمایش interface‌های موجود
				ifaces, _ := net.Interfaces()
				for _, i := range ifaces {
					if i.Flags&net.FlagLoopback != 0 {
						continue
					}
					log.Info("🔌 interface", "name", i.Name)
				}
				os.Exit(1)
			}
			resolvedIface = iface
		}
	}

	var tr transport.Transport
	switch cfg.TransportMode {
	case "obfs":
		key, err := parseObfsKey(cfg.ObfsKey)
		if err != nil {
			log.Error("obfs-key", "err", err)
			os.Exit(1)
		}
		if cfg.SpoofIP != "" {
			tr, err = transport.NewObfsSpoof(cfg.DownloadSrcPort, key,
				resolvedIface, net.ParseIP(resolvedGW),
				net.ParseIP(cfg.SpoofIP).To4(), uint16(cfg.DownloadSrcPort))
			if err != nil {
				log.Error("obfs+spoof", "err", err)
				os.Exit(1)
			}
			log.Warn("⚡ obfs+spoof", "spoof_ip", cfg.SpoofIP)
		} else {
			tr, err = transport.NewObfs(cfg.DownloadSrcPort, key)
			if err != nil {
				log.Error("obfs", "err", err)
				os.Exit(1)
			}
			log.Info("⚡ obfs", "port", cfg.DownloadSrcPort)
		}
	default:
		if cfg.SpoofIP != "" {
			var err error
			tr, err = transport.NewUDPWithSpoof(cfg.DownloadSrcPort,
				resolvedIface, net.ParseIP(resolvedGW),
				net.ParseIP(cfg.SpoofIP).To4(), uint16(cfg.DownloadSrcPort))
			if err != nil {
				log.Error("udp+spoof", "err", err)
				os.Exit(1)
			}
			log.Warn("⚡ UDP+spoof", "spoof_ip", cfg.SpoofIP)
		} else {
			var err error
			tr, err = transport.NewUDP(cfg.DownloadSrcPort)
			if err != nil {
				log.Error("UDP", "err", err)
				os.Exit(1)
			}
			log.Info("⚡ UDP", "port", cfg.DownloadSrcPort)
		}
	}
	defer tr.Close()

	// ── Send pool ────────────────────────────────────────────────────────────
	workers := cfg.UDPWorkers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	sender, err := sendpool.New(sendpool.Config{
		Workers:   workers,
		QueueSize: 8192,
		Transport: tr,
	})
	if err != nil {
		log.Error("send pool", "err", err)
		os.Exit(1)
	}
	defer sender.Close()

	// ── Session manager ──────────────────────────────────────────────────────
	sm := newSessionManager(cfg.MaxClients)

	// ── TCP listener ─────────────────────────────────────────────────────────
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// SO_REUSEADDR — سریع restart بدون wait
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
	ln, err := lc.Listen(context.Background(), "tcp", cfg.ListenAddr)
	if err != nil {
		log.Error("TCP listen", "err", err)
		os.Exit(1)
	}
	defer ln.Close()

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Info("▶ سرور آماده",
		"tcp", cfg.ListenAddr,
		"udp", cfg.DownloadSrcPort,
		"max_clients", cfg.MaxClients,
		"transport", cfg.TransportMode,
	)

	go func() { <-ctx.Done(); ln.Close() }()
	go statsLogger(ctx, log)

	// semaphore برای محدود کردن goroutine های همزمان
	// هر goroutine ~64KB stack → 100K goroutine = 6.4GB
	sem := make(chan struct{}, cfg.MaxClients*2)
	if cap(sem) < 1000 {
		sem = make(chan struct{}, 1000)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			// temporary error — retry
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			continue
		}
		// سعی کن با timeout کوتاه accept کن — نه reject فوری
		accepted := false
		select {
		case sem <- struct{}{}:
			accepted = true
		default:
			select {
			case sem <- struct{}{}:
				accepted = true
			case <-time.After(100 * time.Millisecond):
			}
		}
		if !accepted {
			conn.Close()
			M.RejectedConns.Add(1)
			log.Warn("⚠ connection rejected — max clients reached")
			continue
		}
		go func(c net.Conn) {
			defer func() {
				<-sem
				if r := recover(); r != nil {
					log.Error("panic در handleTCP", "err", r)
				}
			}()
			handleTCP(ctx, c, sm, sender, tcpDial, cfg.FlowWindowBytes, maxPayload, cfg.MTU.AutoFragment, log)
		}(conn)
	}
	log.Info("سرور خاموش شد")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func makeTCPDialer(bindSrc string, timeout time.Duration) func(string) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	if bindSrc != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(bindSrc)}
	}
	return func(addr string) (net.Conn, error) {
		return d.Dial("tcp", addr)
	}
}

// makeTCPDialerWithDNS: dial با DNS cache
func makeTCPDialerWithDNS(bindSrc string, timeout time.Duration, dns *dnscache.Resolver) func(string) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return func(addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if bindSrc != "" {
			d := &net.Dialer{
				Timeout:   timeout,
				LocalAddr: &net.TCPAddr{IP: net.ParseIP(bindSrc)},
			}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := dns.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			// concurrent dial — سریع‌ترین IP که وصل بشه
			type result struct {
				conn net.Conn
				err  error
			}
			ch := make(chan result, len(ips))
			for _, ip := range ips {
				go func(ip net.IP) {
					conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
					ch <- result{conn, err}
				}(ip)
			}
			var firstConn net.Conn
			var lastErr error
			for range ips {
				r := <-ch
				if r.err == nil && firstConn == nil {
					firstConn = r.conn
				} else if r.conn != nil {
					r.conn.Close() // بقیه رو ببند
				} else {
					lastErr = r.err
				}
			}
			if firstConn != nil {
				return firstConn, nil
			}
			return nil, fmt.Errorf("dial %s: %w", addr, lastErr)
		}
		return dns.Dial(ctx, "tcp", addr)
	}
}

func parseObfsKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return nil, fmt.Errorf("obfs-key خالی")
	}
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("obfs-key باید 64 کاراکتر باشه")
	}
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b, err := strconv.ParseUint(hexKey[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		key[i] = byte(b)
	}
	return key, nil
}

func statsLogger(ctx context.Context, log *slog.Logger) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s := M.Snapshot()
			log.Info("📊", "clients", s.ActiveClients, "streams", s.ActiveStreams,
				"up_MB", s.UploadBytes>>20, "dn_MB", s.DownloadBytes>>20)
		}
	}
}

func makeLogger(v bool) *slog.Logger {
	lvl := slog.LevelInfo
	if v {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// pool برای استفاده
var _ = pool.UDPPayload
