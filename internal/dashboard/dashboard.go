// Package dashboard — پنل مانیتورینگ و تنظیمات کلاینت
package dashboard

import (
	cryptoRand "crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Qteam-official/QS-Tunnel/internal/xui"
)

type Stats struct {
	Uptime          string  `json:"uptime"`
	ActiveStreams   int64   `json:"active_streams"`
	ActiveClients   int64   `json:"active_clients"`
	TotalStreams    uint64  `json:"total_streams"`
	UploadMB        float64 `json:"upload_mb"`
	DownloadMB      float64 `json:"download_mb"`
	UploadSpeedKB   float64 `json:"upload_speed_kb"`
	DownloadSpeedKB float64 `json:"download_speed_kb"`
	Reconnects      uint64  `json:"reconnects"`
	DialErrors      uint64  `json:"dial_errors"`
	DNSHits         uint64  `json:"dns_hits"`
	DNSMisses       uint64  `json:"dns_misses"`
	DNSCacheSize    int     `json:"dns_cache_size"`
}

type StatsFn func() Stats
type FlushDNS func()

type Server struct {
	addr       string
	key        string
	configFile string
	statsFn    StatsFn
	flushFn    FlushDNS
	start      time.Time

	mu          sync.Mutex
	lastUpBytes uint64
	lastDnBytes uint64
	lastCheck   time.Time
	upSpeed     float64
	dnSpeed     float64

	sessions   sync.Map
	loginFails atomic.Int64
	lockUntil  atomic.Int64
}

func New(addr, key, configFile string, fn StatsFn, flush FlushDNS) *Server {
	return &Server{
		addr: addr, key: key, configFile: configFile,
		statsFn: fn, flushFn: flush,
		start: time.Now(), lastCheck: time.Now(),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", s.handleAuth)
	mux.HandleFunc("/api/auth/check", s.handleAuthCheck)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/stats", s.protected(s.handleStats))
	mux.HandleFunc("/api/dns/flush", s.protected(s.handleDNSFlush))
	mux.HandleFunc("/api/config/load", s.protected(s.handleConfigLoad))
	mux.HandleFunc("/api/config/save", s.protected(s.handleConfigSave))
	mux.HandleFunc("/api/restart", s.protected(s.handleRestart))
	mux.HandleFunc("/api/xui/setup", s.protected(s.handleXUISetup))
	mux.HandleFunc("/api/xui/outbounds", s.protected(s.handleXUIOutbounds))
	mux.HandleFunc("/api/xui/inbounds", s.protected(s.handleXUIInbounds))
	mux.HandleFunc("/api/xui/routing", s.protected(s.handleXUIRouting))
	srv := &http.Server{Addr: s.addr, Handler: mux, ReadTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func (s *Server) protected(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !s.validToken(token) {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		h(w, r)
	}
}

func (s *Server) validToken(token string) bool {
	if token == "" {
		return false
	}
	v, ok := s.sessions.Load(token)
	if !ok {
		return false
	}
	if time.Now().Unix() > v.(int64) {
		s.sessions.Delete(token)
		return false
	}
	return true
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "POST" {
		http.Error(w, `{"error":"method"}`, 405)
		return
	}
	if s.lockUntil.Load() > time.Now().Unix() {
		http.Error(w, `{"error":"too_many_attempts"}`, 429)
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	ok := subtle.ConstantTimeCompare([]byte(req.Key), []byte(s.key)) == 1
	if !ok {
		if s.loginFails.Add(1) >= 5 {
			s.lockUntil.Store(time.Now().Add(60 * time.Second).Unix())
			s.loginFails.Store(0)
		}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_key"})
		return
	}
	s.loginFails.Store(0)
	// token با crypto/rand — امن‌تر
	tokenBytes := make([]byte, 32)
	cryptoRand.Read(tokenBytes)
	token := fmt.Sprintf("%x", tokenBytes)
	// session 1 ساعته — localStorage در browser نگه میداره
	expiry := time.Now().Add(1 * time.Hour).Unix()
	s.sessions.Store(token, expiry)
	json.NewEncoder(w).Encode(map[string]any{
		"token":   token,
		"expires": expiry,
	})
}

// handleAuthCheck — چک میکنه token هنوز valid هست (برای restore از localStorage)
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.validToken(token) {
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	} else {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{"ok": false})
	}
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := s.statsFn()
	s.mu.Lock()
	now := time.Now()
	if elapsed := now.Sub(s.lastCheck).Seconds(); elapsed >= 1 {
		upB := uint64(stats.UploadMB * 1e6)
		dnB := uint64(stats.DownloadMB * 1e6)
		if s.lastUpBytes > 0 {
			s.upSpeed = float64(upB-s.lastUpBytes) / elapsed / 1024
			s.dnSpeed = float64(dnB-s.lastDnBytes) / elapsed / 1024
		}
		s.lastUpBytes, s.lastDnBytes, s.lastCheck = upB, dnB, now
	}
	stats.UploadSpeedKB, stats.DownloadSpeedKB = s.upSpeed, s.dnSpeed
	s.mu.Unlock()
	up := time.Since(s.start)
	h, m, sec := int(up.Hours()), int(up.Minutes())%60, int(up.Seconds())%60
	if h > 0 {
		stats.Uptime = fmt.Sprintf("%02dh %02dm %02ds", h, m, sec)
	} else {
		stats.Uptime = fmt.Sprintf("%02dm %02ds", m, sec)
	}
	json.NewEncoder(w).Encode(stats)
}

// ─── DNS ─────────────────────────────────────────────────────────────────────

func (s *Server) handleDNSFlush(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.flushFn != nil {
		s.flushFn()
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// ─── Config ───────────────────────────────────────────────────────────────────

func (s *Server) handleConfigLoad(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.configFile == "" {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": "configFile تنظیم نشده"})
		return
	}
	data, err := os.ReadFile(s.configFile)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	var cfg interface{}
	json.Unmarshal(data, &cfg)
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "config": cfg})
}

func (s *Server) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, `{"error":"method"}`, 405)
		return
	}
	if s.configFile == "" {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": "configFile تنظیم نشده"})
		return
	}
	body, _ := io.ReadAll(r.Body)
	var check interface{}
	if err := json.Unmarshal(body, &check); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": "JSON نامعتبر: " + err.Error()})
		return
	}
	// pretty print
	pretty, _ := json.MarshalIndent(check, "", "  ")
	if err := os.WriteFile(s.configFile, pretty, 0644); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "msg": "ذخیره شد"})
}

// ─── Restart ──────────────────────────────────────────────────────────────────

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "msg": "در حال restart..."})
	go func() {
		time.Sleep(800 * time.Millisecond)
		exe, err := os.Executable()
		if err != nil {
			return
		}
		// از exec.Command به جای syscall.Exec استفاده میکنیم
		// این مطمئن‌تره و process جدید با PID جدید میاد
		// os.Exit بعد از Start — process قبلی کامل بسته میشه
		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return
		}
		// منتظر بمون process جدید start بشه
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	}()
}

// ─── 3x-ui ───────────────────────────────────────────────────────────────────

type xuiReq struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Port     int    `json:"port"`
}

func (s *Server) handleXUISetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, `{"error":"method"}`, 405)
		return
	}
	var req xuiReq
	json.NewDecoder(r.Body).Decode(&req)
	if req.URL == "" || req.Password == "" {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": "url و password لازمه"})
		return
	}
	if req.Port == 0 {
		req.Port = 1111
	}
	cfg := xui.Config{PanelURL: req.URL, Username: req.Username, Password: req.Password, InboundPort: req.Port, InboundTag: "qs-upload"}
	client := xui.New(cfg)
	if err := client.Setup(); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "msg": fmt.Sprintf("✅ inbound Mixed روی پورت %d ساخته شد", req.Port)})
}

func (s *Server) handleXUIInbounds(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req xuiReq
	json.NewDecoder(r.Body).Decode(&req)
	if req.URL == "" {
		req.URL = "http://127.0.0.1:2053"
	}
	cfg := xui.Config{PanelURL: req.URL, Username: req.Username, Password: req.Password}
	client := xui.New(cfg)
	inbounds, err := client.ListInbounds()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "inbounds": inbounds})
}

func (s *Server) handleXUIOutbounds(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req xuiReq
	json.NewDecoder(r.Body).Decode(&req)
	if req.URL == "" {
		req.URL = "http://127.0.0.1:2053"
	}
	cfg := xui.Config{PanelURL: req.URL, Username: req.Username, Password: req.Password}
	client := xui.New(cfg)
	outbounds, err := client.ListOutbounds()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "outbounds": outbounds})
}

func (s *Server) handleXUIRouting(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, `{"error":"method"}`, 405)
		return
	}
	var req struct {
		xuiReq
		InboundTag  string `json:"inbound_tag"`
		OutboundTag string `json:"outbound_tag"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.InboundTag == "" || req.OutboundTag == "" {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": "inbound_tag و outbound_tag لازمن"})
		return
	}
	if req.URL == "" {
		req.URL = "http://127.0.0.1:2053"
	}
	cfg := xui.Config{PanelURL: req.URL, Username: req.Username, Password: req.Password}
	client := xui.New(cfg)
	if err := client.SetupRouting(req.InboundTag, req.OutboundTag); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"ok":  true,
		"msg": fmt.Sprintf("✅ routing اعمال شد: %s → %s", req.InboundTag, req.OutboundTag),
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>QS-Tunnel</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
:root{
  --cy:#00f5ff;--gr:#00ff9f;--pk:#ff2d78;--or:#ff9500;--pu:#bf5fff;--ye:#ffe600;
  --bg:#020510;--bg2:#030818;--tx:#c8dff0;--dm:#3d5a7a;--bdr:rgba(0,245,255,.1);
  --card:rgba(0,245,255,.025);
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);font-family:'Share Tech Mono',monospace;color:var(--tx);
  min-height:100vh;overflow-x:hidden}

/* ── Grid BG ──────────────────────────────────────────────────────────── */
.grid-bg{position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:
    linear-gradient(rgba(0,245,255,.025) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,245,255,.025) 1px,transparent 1px);
  background-size:44px 44px;animation:g-move 25s linear infinite}
@keyframes g-move{to{background-position:44px 44px}}
.scan{position:fixed;inset:0;pointer-events:none;z-index:1;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,
    rgba(0,0,0,.06) 2px,rgba(0,0,0,.06) 4px)}

/* ── LOGIN ────────────────────────────────────────────────────────────── */
#login{position:fixed;inset:0;z-index:200;display:flex;align-items:center;
  justify-content:center;background:rgba(2,5,16,.98)}

.l-rings{position:absolute;inset:0;overflow:hidden}
.ring{position:absolute;border-radius:50%;top:50%;left:50%;
  transform:translate(-50%,-50%);border:1px solid;animation:rpulse 4s ease-in-out infinite}
.r1{width:500px;height:500px;border-color:rgba(0,245,255,.08);animation-delay:0s}
.r2{width:720px;height:720px;border-color:rgba(0,245,255,.05);animation-delay:.7s}
.r3{width:950px;height:950px;border-color:rgba(0,245,255,.03);animation-delay:1.4s}
.r4{width:1200px;height:1200px;border-color:rgba(0,245,255,.015);animation-delay:2.1s}
@keyframes rpulse{0%,100%{opacity:.5;transform:translate(-50%,-50%) scale(1)}
  50%{opacity:1;transform:translate(-50%,-50%) scale(1.015)}}

.l-particles{position:absolute;inset:0;overflow:hidden}
.pt{position:absolute;border-radius:50%;background:var(--cy);animation:pfloat linear infinite;opacity:0}
@keyframes pfloat{0%{transform:translateY(110vh);opacity:0}
  8%{opacity:.7}85%{opacity:.2}100%{transform:translateY(-5vh) translateX(80px);opacity:0}}

.l-box{position:relative;z-index:2;width:min(400px,94vw);
  background:linear-gradient(145deg,rgba(0,245,255,.04),rgba(0,245,255,.01));
  border:1px solid rgba(0,245,255,.2);border-radius:14px;padding:42px 36px;
  box-shadow:0 0 100px rgba(0,245,255,.05),0 0 250px rgba(0,245,255,.02),
    inset 0 1px 0 rgba(0,245,255,.15),inset 0 -1px 0 rgba(0,245,255,.05);
  animation:boxin .7s cubic-bezier(.34,1.56,.64,1) both}
@keyframes boxin{from{opacity:0;transform:scale(.88) translateY(24px)}to{opacity:1;transform:none}}

.l-logo{text-align:center;margin-bottom:6px}
.l-title{font-family:'Orbitron',sans-serif;font-size:30px;font-weight:900;
  color:var(--cy);letter-spacing:8px;display:block;
  text-shadow:0 0 25px var(--cy),0 0 70px rgba(0,245,255,.25);
  animation:lflicker 7s infinite}
.l-title s{color:var(--pk);text-decoration:none}
.l-sub{font-size:8px;letter-spacing:6px;color:var(--dm);display:block;margin-top:5px}
@keyframes lflicker{0%,87%,100%{opacity:1}88%{opacity:.25}90%{opacity:.85}92%{opacity:.4}94%{opacity:1}}

.l-div{height:1px;background:linear-gradient(90deg,transparent,rgba(0,245,255,.25),transparent);
  margin:28px 0}

.l-field{margin-bottom:18px}
.l-field label{font-size:7px;letter-spacing:4px;color:var(--dm);display:block;
  margin-bottom:7px;text-transform:uppercase;transition:color .2s}
.l-field:focus-within label{color:var(--cy)}
.l-field input{width:100%;background:rgba(0,245,255,.04);
  border:1px solid rgba(0,245,255,.15);border-radius:7px;
  color:var(--cy);font-family:'Share Tech Mono',monospace;font-size:14px;
  padding:12px 16px;outline:none;transition:all .25s;letter-spacing:2px}
.l-field input:focus{border-color:rgba(0,245,255,.55);
  box-shadow:0 0 0 3px rgba(0,245,255,.07),0 0 25px rgba(0,245,255,.08)}
.l-field input::placeholder{color:rgba(0,245,255,.18)}

.l-btn{width:100%;padding:14px;margin-top:6px;cursor:pointer;
  background:linear-gradient(135deg,rgba(0,245,255,.14),rgba(0,245,255,.05));
  border:1px solid rgba(0,245,255,.32);border-radius:7px;
  color:var(--cy);font-family:'Orbitron',sans-serif;font-size:10px;
  font-weight:700;letter-spacing:5px;transition:all .28s;
  position:relative;overflow:hidden}
.l-btn::after{content:'';position:absolute;top:0;left:-100%;
  width:100%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.08),transparent);
  transition:left .45s}
.l-btn:hover::after{left:100%}
.l-btn:hover{background:rgba(0,245,255,.2);
  box-shadow:0 0 35px rgba(0,245,255,.18),0 0 8px rgba(0,245,255,.3);letter-spacing:7px}
.l-btn:disabled{opacity:.5;cursor:wait;letter-spacing:5px}

.l-err{font-size:10px;color:var(--pk);text-align:center;min-height:16px;
  margin-top:10px;animation:shake .32s ease}
@keyframes shake{0%,100%{transform:translateX(0)}
  25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}

/* Corner deco */
.cn{position:absolute;width:22px;height:22px}
.cn::before,.cn::after{content:'';position:absolute;background:var(--cy);
  box-shadow:0 0 8px var(--cy)}
.cn::before{width:100%;height:2px;top:0;left:0}
.cn::after{width:2px;height:100%;top:0;left:0}
.cn.tl{top:-1px;left:-1px} .cn.tr{top:-1px;right:-1px;transform:scaleX(-1)}
.cn.bl{bottom:-1px;left:-1px;transform:scaleY(-1)} .cn.br{bottom:-1px;right:-1px;transform:scale(-1)}

/* ── APP ──────────────────────────────────────────────────────────────── */
#app{display:none;position:relative;z-index:2;min-height:100vh}

/* Header */
.hdr{border-bottom:1px solid var(--bdr);padding:10px 18px;
  display:flex;align-items:center;justify-content:space-between;
  background:rgba(2,5,16,.85);backdrop-filter:blur(12px);
  position:sticky;top:0;z-index:50}
.h-logo{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:900;
  color:var(--cy);letter-spacing:4px;text-shadow:0 0 10px var(--cy);
  animation:lflicker 7s infinite}
.h-logo s{color:var(--pk);text-decoration:none}
.h-logo sub{font-size:7px;color:var(--dm);letter-spacing:3px;margin-left:4px}
.h-r{display:flex;align-items:center;gap:12px}
.h-upt{font-size:8px;color:var(--dm);font-variant-numeric:tabular-nums}
.h-dot{width:7px;height:7px;border-radius:50%;background:var(--gr);
  box-shadow:0 0 8px var(--gr);animation:dpulse 2s infinite}
@keyframes dpulse{0%,100%{box-shadow:0 0 6px var(--gr)}
  50%{box-shadow:0 0 18px var(--gr),0 0 35px rgba(0,255,159,.2)}}
.h-exit{font-size:8px;color:var(--dm);background:none;
  border:1px solid rgba(255,255,255,.08);border-radius:4px;
  padding:3px 9px;cursor:pointer;letter-spacing:1px;transition:all .2s}
.h-exit:hover{color:var(--pk);border-color:rgba(255,45,120,.4)}

/* Tabs */
.tabs{display:flex;padding:0 18px;border-bottom:1px solid rgba(0,245,255,.06);
  background:linear-gradient(180deg,rgba(3,8,24,.9),rgba(2,5,16,.6));
  overflow-x:auto;gap:0}
.tab{font-size:8px;letter-spacing:3px;padding:10px 18px;cursor:pointer;
  color:var(--dm);border-bottom:2px solid transparent;
  transition:all .22s;white-space:nowrap;position:relative}
.tab.on{color:var(--cy);border-bottom-color:var(--cy)}
.tab.on::before{content:'';position:absolute;bottom:-2px;left:50%;
  transform:translateX(-50%);
  width:5px;height:5px;border-radius:50%;
  background:var(--cy);box-shadow:0 0 8px var(--cy)}
.tab:hover:not(.on){color:rgba(200,223,240,.7)}

/* Panels */
.pnl{display:none;padding:14px 18px;max-width:1100px;margin:0 auto;
  animation:pin .22s ease both}
.pnl.on{display:block}
@keyframes pin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* ── MONITOR ──────────────────────────────────────────────────────────── */
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:8px;margin-bottom:14px}
.card{border:1px solid var(--bdr);border-radius:8px;background:var(--card);
  padding:13px;position:relative;overflow:hidden;transition:all .3s;cursor:default}
.card::before{content:'';position:absolute;top:0;left:0;width:2px;height:100%;
  background:linear-gradient(180deg,var(--ac),rgba(0,0,0,0))}
.card::after{content:'';position:absolute;top:-50%;right:-50%;
  width:100%;height:100%;
  background:radial-gradient(circle,rgba(var(--acr),.07),transparent 65%);
  opacity:0;transition:opacity .35s}
.card:hover{transform:translateY(-2px);border-color:rgba(0,245,255,.18)}
.card:hover::after{opacity:1}
.c-l{font-size:7px;letter-spacing:3px;color:var(--dm);text-transform:uppercase;margin-bottom:8px}
.c-v{font-family:'Orbitron',sans-serif;font-size:20px;font-weight:700;
  color:var(--ac);text-shadow:0 0 12px var(--ac);transition:all .3s}
.c-s{font-size:8px;color:var(--dm);margin-top:3px}
.acy{--ac:var(--cy);--acr:0,245,255}
.acg{--ac:var(--gr);--acr:0,255,159}
.acp{--ac:var(--pk);--acr:255,45,120}
.aco{--ac:var(--or);--acr:255,149,0}
.acu{--ac:var(--pu);--acr:191,95,255}

/* Speed section */
.sec-t{font-family:'Orbitron',sans-serif;font-size:7px;letter-spacing:4px;
  color:var(--dm);text-transform:uppercase;margin-bottom:10px;
  padding-bottom:5px;border-bottom:1px solid rgba(0,245,255,.05)}
.spd-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.spd-l{width:70px;font-size:9px}
.bar-w{flex:1;height:4px;background:rgba(0,0,0,.4);border-radius:2px;
  overflow:hidden;border:1px solid rgba(0,245,255,.06)}
.bar{height:100%;border-radius:2px;transition:width 1.4s cubic-bezier(.4,0,.2,1);min-width:2px}
.bar-up{background:linear-gradient(90deg,var(--or),var(--ye));
  box-shadow:0 0 8px rgba(255,149,0,.6)}
.bar-dn{background:linear-gradient(90deg,var(--cy),var(--gr));
  box-shadow:0 0 8px rgba(0,245,255,.6)}
.spd-v{width:82px;font-size:9px;text-align:right}

/* Chart */
.chart-wrap{border:1px solid rgba(0,245,255,.08);border-radius:8px;
  background:rgba(0,0,0,.35);padding:14px;margin-top:12px;position:relative;
  overflow:hidden}
.chart-wrap::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(0,245,255,.15),transparent)}

/* ── SETUP ────────────────────────────────────────────────────────────── */
.sc{border:1px solid var(--bdr);border-radius:8px;
  background:linear-gradient(160deg,rgba(0,245,255,.025),rgba(0,0,0,.1));
  padding:18px;margin-bottom:12px;transition:border-color .3s}
.sc:hover{border-color:rgba(0,245,255,.14)}
.sc-t{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:3px;
  color:var(--cy);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.bdg{font-size:7px;padding:2px 7px;border-radius:3px;letter-spacing:2px;
  background:rgba(0,255,159,.07);color:var(--gr);border:1px solid rgba(0,255,159,.18)}
.bdg.w{background:rgba(255,149,0,.07);color:var(--or);border-color:rgba(255,149,0,.18)}

.fg{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:9px}
.sf{display:flex;flex-direction:column;gap:4px}
.sf label{font-size:7px;letter-spacing:2px;color:var(--dm);text-transform:uppercase}
.sf .hint{font-size:6px;color:rgba(61,90,122,.8);margin-left:3px}
.sf input,.sf select{background:rgba(0,0,0,.3);
  border:1px solid rgba(0,245,255,.1);border-radius:5px;
  color:var(--tx);font-family:'Share Tech Mono',monospace;font-size:11px;
  padding:7px 10px;outline:none;transition:all .22s;width:100%}
.sf input:focus,.sf select:focus{border-color:rgba(0,245,255,.45);
  box-shadow:0 0 0 3px rgba(0,245,255,.06),0 0 12px rgba(0,245,255,.06)}
.sf select{cursor:pointer;background-color:rgba(0,0,0,.3)}

/* Outbound list */
.ob-list{margin-top:10px;border:1px solid var(--bdr);border-radius:6px;
  max-height:190px;overflow-y:auto;background:rgba(0,0,0,.2)}
.ob-list::-webkit-scrollbar{width:3px}
.ob-list::-webkit-scrollbar-thumb{background:rgba(0,245,255,.2)}
.ob-item{display:flex;align-items:center;gap:9px;padding:8px 12px;
  border-bottom:1px solid rgba(0,245,255,.04);cursor:pointer;transition:all .15s;font-size:9px}
.ob-item:last-child{border-bottom:none}
.ob-item:hover{background:rgba(0,245,255,.06)}
.ob-item.sel{background:rgba(0,245,255,.1);border-left:2px solid var(--cy)}
.ob-tag{font-family:'Orbitron',sans-serif;font-size:8px;color:var(--cy)}
.ob-tag.sel-glow{text-shadow:0 0 8px var(--cy)}
.ob-pro{color:var(--dm);margin-left:auto;font-size:7px;
  padding:1px 6px;border-radius:10px;background:rgba(0,245,255,.06)}

/* Row buttons */
.row{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.btn{font-family:'Share Tech Mono',monospace;font-size:8px;letter-spacing:2px;
  padding:8px 14px;border-radius:5px;cursor:pointer;border:none;
  transition:all .22s;position:relative;overflow:hidden}
.btn::before{content:'';position:absolute;inset:0;
  background:rgba(255,255,255,.07);opacity:0;transition:opacity .15s}
.btn:active::before{opacity:1}
.btn:disabled{opacity:.4;cursor:wait}
.bp{background:rgba(0,245,255,.08);color:var(--cy);border:1px solid rgba(0,245,255,.2)}
.bp:hover{background:rgba(0,245,255,.16);box-shadow:0 0 18px rgba(0,245,255,.12)}
.bs{background:rgba(0,255,159,.07);color:var(--gr);border:1px solid rgba(0,255,159,.18)}
.bs:hover{background:rgba(0,255,159,.14)}
.bd{background:rgba(255,45,120,.05);color:var(--pk);border:1px solid rgba(255,45,120,.15)}
.bd:hover{background:rgba(255,45,120,.1)}

/* Status messages */
.stl{margin-top:9px;padding:8px 12px;border-radius:5px;font-size:9px;
  border:1px solid;display:none;animation:stin .2s ease}
@keyframes stin{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:none}}
.stl.ok{background:rgba(0,255,159,.04);border-color:rgba(0,255,159,.18);color:var(--gr)}
.stl.er{background:rgba(255,45,120,.04);border-color:rgba(255,45,120,.18);color:var(--pk)}
.stl.if{background:rgba(0,245,255,.04);border-color:rgba(0,245,255,.18);color:var(--cy)}
.stl.if::before{content:'';display:inline-block;
  width:8px;height:8px;border:2px solid var(--cy);border-top-color:transparent;
  border-radius:50%;animation:spin .7s linear infinite;
  margin-right:7px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}

/* Config section */
.cfg-sec{margin-bottom:16px}
.cfg-sec-t{font-family:'Orbitron',sans-serif;font-size:7px;letter-spacing:3px;
  color:var(--pu);margin-bottom:10px;padding-bottom:5px;
  border-bottom:1px solid rgba(191,95,255,.12)}
.cfg-g{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:9px}
.tgl{display:flex;align-items:center;gap:8px;padding:7px 11px;
  background:rgba(0,0,0,.25);border:1px solid rgba(0,245,255,.08);border-radius:5px}
.tgl input{width:14px;height:14px;cursor:pointer;accent-color:var(--cy)}
.tgl label{font-size:10px;cursor:pointer;color:var(--tx)}

/* Footer */
.ft{padding:8px 18px;border-top:1px solid rgba(0,245,255,.05);
  font-size:7px;color:var(--dm);display:flex;justify-content:space-between;letter-spacing:3px}
.blink{animation:blk 1.6s infinite}
@keyframes blk{0%,100%{opacity:1}50%{opacity:.15}}

@media(max-width:500px){
  .h-logo{font-size:12px;letter-spacing:3px}
  .tabs .tab{padding:9px 10px;font-size:7px}
  .pnl{padding:11px}
  .fg,.cfg-g{grid-template-columns:1fr}
}
</style>
</head>
<body>

<div class="grid-bg"></div>
<div class="scan"></div>

<!-- ════ LOGIN ════════════════════════════════════════════════════════════ -->
<div id="login">
  <div class="l-rings">
    <div class="ring r1"></div><div class="ring r2"></div>
    <div class="ring r3"></div><div class="ring r4"></div>
  </div>
  <div class="l-particles" id="pts"></div>
  <div class="l-box">
    <div class="cn tl"></div><div class="cn tr"></div>
    <div class="cn bl"></div><div class="cn br"></div>
    <div class="l-logo">
      <span class="l-title">QS<s>·</s>TUNNEL</span>
      <span class="l-sub">CLIENT DASHBOARD</span>
    </div>
    <div class="l-div"></div>
    <div class="l-field">
      <label>ACCESS KEY</label>
      <input type="password" id="lk" placeholder="enter access key" autocomplete="off">
    </div>
    <button class="l-btn" id="lbtn" onclick="doAuth()">⬡ &nbsp; AUTHENTICATE</button>
    <div class="l-err" id="lerr"></div>
  </div>
</div>

<!-- ════ APP ══════════════════════════════════════════════════════════════ -->
<div id="app">
  <div class="hdr">
    <div class="h-logo">QS<s>·</s>TUNNEL<sub>CLIENT</sub></div>
    <div class="h-r">
      <span class="h-upt" id="upt">--</span>
      <div class="h-dot"></div>
      <button class="h-exit" onclick="doLogout()">EXIT</button>
    </div>
  </div>

  <div class="tabs">
    <div class="tab on" onclick="sw('Mon',this)">📊 Monitor</div>
    <div class="tab" onclick="sw('Set',this)">⚙ 3x-ui</div>
    <div class="tab" onclick="sw('Cfg',this)">📋 Config</div>
  </div>

  <!-- ── MONITOR ── -->
  <div class="pnl on" id="tMon">
    <div class="sg">
      <div class="card acy">
        <div class="c-l">Streams</div>
        <div class="c-v" id="c-str">--</div>
        <div class="c-s">Total <span id="c-tot">--</span></div>
      </div>
      <div class="card aco">
        <div class="c-l">Upload</div>
        <div class="c-v" id="c-up">--</div>
        <div class="c-s">MB</div>
      </div>
      <div class="card acp">
        <div class="c-l">Download</div>
        <div class="c-v" id="c-dn">--</div>
        <div class="c-s">MB</div>
      </div>
      <div class="card acu">
        <div class="c-l">Reconnects</div>
        <div class="c-v" id="c-rc">--</div>
        <div class="c-s">Auto</div>
      </div>
    </div>

    <div class="sec-t">Live Throughput</div>
    <div class="spd-row">
      <span class="spd-l" style="color:var(--or)">⬆ Upload</span>
      <div class="bar-w"><div class="bar bar-up" id="b-up" style="width:0"></div></div>
      <span class="spd-v" id="s-up" style="color:var(--or)">--</span>
    </div>
    <div class="spd-row">
      <span class="spd-l" style="color:var(--cy)">⬇ Download</span>
      <div class="bar-w"><div class="bar bar-dn" id="b-dn" style="width:0"></div></div>
      <span class="spd-v" id="s-dn" style="color:var(--cy)">--</span>
    </div>

    <div class="chart-wrap">
      <canvas id="chart" height="100" style="width:100%"></canvas>
    </div>
  </div>

  <!-- ── 3x-ui SETUP ── -->
  <div class="pnl" id="tSet">
    <!-- connection -->
    <div class="sc">
      <div class="sc-t">🔌 3x-ui Connection</div>
      <div class="fg">
        <div class="sf"><label>Panel URL</label>
          <input id="xu" placeholder="http://127.0.0.1:2053"></div>
        <div class="sf"><label>Username</label>
          <input id="xn"></div>
        <div class="sf"><label>Password</label>
          <input type="password" id="xp"></div>
        <div class="sf"><label>Upload Port</label>
          <input type="number" id="xo" value="1111"></div>
      </div>
      <div class="row">
        <button class="btn bp" onclick="xuSetup()">⬡ ساخت inbound qs-upload</button>
        <button class="btn bp" id="loadBtn" onclick="loadAll()">↺ دریافت inbounds & outbounds</button>
      </div>
      <div class="stl" id="xs"></div>
    </div>

    <!-- routing upload -->
    <div class="sc">
      <div class="sc-t">🔀 Routing Upload <span class="bdg w" id="upTag">inbound-127.0.0.1:1111</span></div>
      <div style="font-size:8px;color:var(--dm);margin-bottom:10px;line-height:1.7">
        ترافیک upload inbound به کدوم outbound روت بشه؟
      </div>
      <div class="ob-list" id="outList">
        <div style="padding:12px;color:var(--dm);font-size:9px;text-align:center">
          ابتدا "دریافت inbounds & outbounds" رو بزن
        </div>
      </div>
      <div class="sf" style="margin-top:9px">
        <label>Outbound انتخاب شده</label>
        <input id="selOut" placeholder="روی outbound کلیک کن..." readonly>
      </div>
      <div class="row">
        <button class="btn bs" onclick="applyUpRoute()">✓ اعمال routing</button>
      </div>
      <div class="stl" id="rs1"></div>
    </div>

    <!-- routing socks 7070 -->
    <div class="sc">
      <div class="sc-t">🔀 Routing Socks <span class="bdg w">127.0.0.1:7070</span></div>
      <div style="font-size:8px;color:var(--dm);margin-bottom:10px;line-height:1.7">
        کدوم inbound از 3x-ui به socks <span style="color:var(--cy)">127.0.0.1:7070</span> وصل بشه؟
      </div>
      <div class="ob-list" id="inList">
        <div style="padding:12px;color:var(--dm);font-size:9px;text-align:center">
          ابتدا "دریافت inbounds & outbounds" رو بزن
        </div>
      </div>
      <div class="sf" style="margin-top:9px">
        <label>Inbound انتخاب شده</label>
        <input id="selIn" placeholder="روی inbound کلیک کن..." readonly>
      </div>
      <div class="row">
        <button class="btn bs" onclick="applySocksRoute()">✓ اعمال routing</button>
      </div>
      <div class="stl" id="rs2"></div>
    </div>
  </div>

  <!-- ── CONFIG ── -->
  <div class="pnl" id="tCfg">
    <div class="sc">
      <div class="sc-t">📋 client.json <span class="bdg">live config</span></div>
      <div style="font-size:8px;color:var(--dm);margin-bottom:16px;line-height:1.7">
        ذخیره → هسته فعلی متوقف میشه → هسته جدید با config جدید اجرا میشه
      </div>

      <div class="cfg-sec">
        <div class="cfg-sec-t">⬡ اتصال</div>
        <div class="cfg-g">
          <div class="sf"><label>Server Addr <span class="hint">IP:port</span></label>
            <input id="f-srv" placeholder="1.2.3.4:9000"></div>
          <div class="sf"><label>My Public IP <span class="hint">خالی=auto</span></label>
            <input id="f-ip" placeholder="auto از route table"></div>
          <div class="sf"><label>Upload Proxy</label>
            <input id="f-prx" placeholder="127.0.0.1:10808"></div>
          <div class="sf"><label>Local SOCKS5</label>
            <input id="f-sk" placeholder="127.0.0.1:1080"></div>
          <div class="sf"><label>Download Port</label>
            <input type="number" id="f-dlp" placeholder="8000"></div>
          <div class="sf"><label>Max Streams</label>
            <input type="number" id="f-ms" placeholder="512"></div>
        </div>
      </div>

      <div class="cfg-sec">
        <div class="cfg-sec-t">⬡ Transport</div>
        <div class="cfg-g">
          <div class="sf"><label>Mode</label>
            <select id="f-tr" onchange="onTr()">
              <option value="udp">udp — fast</option>
              <option value="obfs">obfs — AES-256-GCM</option>
            </select></div>
          <div class="sf" id="f-obfs-wrap" style="display:none">
            <label>Obfs Key</label>
            <input id="f-ok" placeholder="64 hex chars"></div>
        </div>
      </div>

      <div class="cfg-sec">
        <div class="cfg-sec-t">⬡ Dashboard</div>
        <div class="cfg-g">
          <div class="sf"><label>Addr</label>
            <input id="f-da" placeholder="127.0.0.1:8081"></div>
          <div class="sf"><label>Key</label>
            <input id="f-dk" placeholder="access key"></div>
        </div>
      </div>

      <div class="cfg-sec">
        <div class="cfg-sec-t">⬡ 3x-ui</div>
        <div class="cfg-g">
          <div class="sf"><label>Panel URL</label>
            <input id="f-xu" placeholder="http://127.0.0.1:2053"></div>
          <div class="sf"><label>Username</label>
            <input id="f-xn" placeholder="admin"></div>
          <div class="sf"><label>Password</label>
            <input type="password" id="f-xp"></div>
          <div class="sf"><label>Inbound Port</label>
            <input type="number" id="f-xpo" placeholder="1111"></div>
        </div>
      </div>

      <div class="cfg-sec">
        <div class="cfg-sec-t">⬡ سایر</div>
        <div class="cfg-g">
          <div class="sf"><label>Metrics Addr</label>
            <input id="f-met" placeholder="127.0.0.1:9091"></div>
          <div class="sf">
            <div class="tgl">
              <input type="checkbox" id="f-vb">
              <label for="f-vb">Verbose logging</label>
            </div>
          </div>
        </div>
      </div>

      <div class="row">
        <button class="btn bp" onclick="loadCfg()">↺ بارگذاری</button>
        <button class="btn bs" id="saveBtn" onclick="saveCfg()">💾 ذخیره و Restart</button>
      </div>
      <div class="stl" id="cfg-st"></div>
    </div>
  </div>

  <div class="ft">
    <span>QS-TUNNEL CLIENT</span>
    <span class="blink">● LIVE</span>
  </div>
</div>

<script>
'use strict';
// ── Constants ────────────────────────────────────────────────────────────────
const SESSION_KEY = 'qs_tok';
const SESSION_EXP = 'qs_exp';
const CHART_N = 60;

// ── State ────────────────────────────────────────────────────────────────────
let tok = '';
let selOutTag = '', selInTag = '';
const upH = new Array(CHART_N).fill(0);
const dnH = new Array(CHART_N).fill(0);
let chart, ctx;

// ── Particles ────────────────────────────────────────────────────────────────
(function(){
  const c = document.getElementById('pts');
  for(let i = 0; i < 30; i++){
    const p = document.createElement('div');
    p.className = 'pt';
    const r1=Math.random(), r2=Math.random(), r3=Math.random(), r4=Math.random(), r5=Math.random();
    p.style.cssText = 'left:' + Math.round(r1*100) + '%;'
      + 'width:' + (1+r2).toFixed(1) + 'px;height:' + (1+r2).toFixed(1) + 'px;'
      + 'animation-duration:' + (5+r3*10).toFixed(1) + 's;'
      + 'animation-delay:' + (r4*8).toFixed(1) + 's;'
      + 'opacity:' + (0.2+r5*0.6).toFixed(2);
    c.appendChild(p);
  }
})();

// ── Session Restore ───────────────────────────────────────────────────────────
(async function(){
  const saved = localStorage.getItem(SESSION_KEY);
  const exp   = parseInt(localStorage.getItem(SESSION_EXP) || '0', 10);
  if(!saved || Date.now()/1000 > exp) return;
  // verify با server
  try {
    const r = await fetch('/api/auth/check', {headers:{Authorization:'Bearer '+saved}});
    if(r.status === 200){
      const d = await r.json();
      if(d.ok){ tok = saved; showApp(); return; }
    }
  } catch {}
  localStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(SESSION_EXP);
})();

// ── Auth ─────────────────────────────────────────────────────────────────────
async function doAuth(){
  const k = document.getElementById('lk').value.trim();
  const btn = document.getElementById('lbtn');
  if(!k){ showErr('⚠ ACCESS KEY REQUIRED'); return; }
  btn.textContent = '⟳  VERIFYING...';
  btn.disabled = true;
  try{
    const r = await fetch('/api/auth',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({key:k})
    });
    const d = await r.json();
    if(d.token){
      tok = d.token;
      // ذخیره در localStorage — session 1 ساعته
      localStorage.setItem(SESSION_KEY, tok);
      localStorage.setItem(SESSION_EXP, String(d.expires || Math.floor(Date.now()/1000)+3600));
      showApp();
    } else {
      showErr('⚠ ACCESS DENIED');
      btn.textContent = '⬡  AUTHENTICATE';
      btn.disabled = false;
    }
  } catch {
    showErr('⚠ CONNECTION ERROR');
    btn.textContent = '⬡  AUTHENTICATE';
    btn.disabled = false;
  }
}

function showErr(msg){
  const e = document.getElementById('lerr');
  e.textContent = msg;
  e.style.animation = 'none';
  requestAnimationFrame(()=>{ e.style.animation = 'shake .32s ease'; });
  setTimeout(()=>e.textContent='', 3000);
}

function showApp(){
  document.getElementById('login').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  initChart();
  tick();
  setInterval(tick, 2000);
  loadCfg();
}

document.getElementById('lk').addEventListener('keydown', e=>{if(e.key==='Enter')doAuth()});

function doLogout(){
  tok = '';
  localStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(SESSION_EXP);
  document.getElementById('app').style.display = 'none';
  document.getElementById('login').style.display = 'flex';
  document.getElementById('lk').value = '';
  document.getElementById('lbtn').textContent = '⬡  AUTHENTICATE';
  document.getElementById('lbtn').disabled = false;
}

// ── Tabs ─────────────────────────────────────────────────────────────────────
function sw(id, el){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  document.querySelectorAll('.pnl').forEach(p=>p.classList.remove('on'));
  el.classList.add('on');
  document.getElementById('t'+id).classList.add('on');
}

// ── Chart ─────────────────────────────────────────────────────────────────────
function initChart(){
  chart = document.getElementById('chart');
  ctx = chart.getContext('2d');
  rsz(); window.addEventListener('resize', rsz);
}
function rsz(){
  const r = window.devicePixelRatio||1;
  chart.width  = chart.offsetWidth * r;
  chart.height = 100 * r;
  ctx.scale(r, r);
}
function drawChart(){
  const w = chart.offsetWidth, h = 100;
  ctx.clearRect(0,0,w,h);
  const mx = Math.max(...upH,...dnH, 1);
  const step = w / (CHART_N-1);

  // grid lines
  ctx.strokeStyle = 'rgba(0,245,255,.04)'; ctx.lineWidth = 1;
  for(let i=1;i<5;i++){
    const y = h/5*i;
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke();
  }
  // vertical guides
  ctx.strokeStyle = 'rgba(0,245,255,.02)';
  for(let i=1;i<6;i++){
    const x = w/6*i;
    ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,h); ctx.stroke();
  }

  function drawLine(data, col, gFill){
    ctx.beginPath();
    data.forEach((v,i)=>{
      const x = i*step, y = h-5-(v/mx)*(h-10);
      i ? ctx.lineTo(x,y) : ctx.moveTo(x,y);
    });
    ctx.strokeStyle = col; ctx.lineWidth = 1.5;
    ctx.shadowColor = col; ctx.shadowBlur = 6;
    ctx.stroke(); ctx.shadowBlur = 0;
    // fill
    ctx.lineTo((CHART_N-1)*step, h); ctx.lineTo(0,h); ctx.closePath();
    const g = ctx.createLinearGradient(0,0,0,h);
    g.addColorStop(0, gFill); g.addColorStop(1, 'transparent');
    ctx.fillStyle = g; ctx.fill();
  }

  drawLine(dnH, '#00f5ff', 'rgba(0,245,255,.12)');
  drawLine(upH, '#ff9500', 'rgba(255,149,0,.1)');

  // labels
  ctx.fillStyle = 'rgba(0,245,255,.35)';
  ctx.font = '8px Share Tech Mono';
  ctx.fillText(fmtSpd(mx), 5, 14);
}

function fmtSpd(kb){ return kb>=1024?(kb/1024).toFixed(1)+' MB/s':kb.toFixed(0)+' KB/s'; }

function setEl(id,v){ const e=document.getElementById(id); if(e)e.textContent=v; }

// ── Stats ─────────────────────────────────────────────────────────────────────
async function tick(){
  try{
    const r = await fetch('/api/stats',{headers:{Authorization:'Bearer '+tok}});
    if(r.status === 401){ doLogout(); return; }
    const s = await r.json();
    setEl('upt', s.uptime);
    animVal('c-str', s.active_streams);
    setEl('c-tot', s.total_streams);
    animVal('c-up', s.upload_mb?.toFixed(1));
    animVal('c-dn', s.download_mb?.toFixed(1));
    animVal('c-rc', s.reconnects);
    const uk = s.upload_speed_kb||0, dk = s.download_speed_kb||0, mx = 10240;
    document.getElementById('b-up').style.width = Math.min(uk/mx*100,100)+'%';
    document.getElementById('b-dn').style.width = Math.min(dk/mx*100,100)+'%';
    setEl('s-up', fmtSpd(uk));
    setEl('s-dn', fmtSpd(dk));
    upH.push(uk); upH.shift();
    dnH.push(dk); dnH.shift();
    if(chart) drawChart();
  } catch {}
}

function animVal(id, newVal){
  const el = document.getElementById(id);
  if(!el) return;
  const v = String(newVal);
  if(el.textContent !== v){
    el.style.transition = 'transform .15s,opacity .15s';
    el.style.transform = 'scale(1.12)'; el.style.opacity = '.6';
    setTimeout(()=>{
      el.textContent = v;
      el.style.transform = ''; el.style.opacity = '';
    }, 120);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function show(id, type, msg, dur=5000){
  const e = document.getElementById(id);
  if(!e) return;
  e.className = 'stl ' + type;
  e.textContent = msg;
  e.style.display = 'block';
  if(dur > 0) setTimeout(()=>e.style.display='none', dur);
}

function xuiBody(){
  return {
    url:      document.getElementById('xu').value || 'http://127.0.0.1:2053',
    username: document.getElementById('xn').value || 'admin',
    password: document.getElementById('xp').value,
    port:     +(document.getElementById('xo').value || 1111)
  };
}

function hdrs(){ return {'Content-Type':'application/json','Authorization':'Bearer '+tok}; }

// ── 3x-ui ────────────────────────────────────────────────────────────────────
async function xuSetup(){
  if(!document.getElementById('xp').value){ show('xs','er','⚠ رمز 3x-ui رو وارد کن'); return; }
  show('xs','if','در حال ساخت inbound qs-upload...',0);
  try{
    const r = await fetch('/api/xui/setup',{method:'POST',headers:hdrs(),body:JSON.stringify(xuiBody())});
    const d = await r.json();
    show('xs', d.ok?'ok':'er', d.ok?'✅ '+d.msg:'❌ '+d.msg);
    if(d.ok) setTimeout(loadAll, 500);
  } catch { show('xs','er','❌ خطای شبکه'); }
}

async function loadAll(){
  const btn = document.getElementById('loadBtn');
  btn.disabled = true;
  show('xs','if','در حال دریافت...',0);
  try{
    const body = JSON.stringify(xuiBody());
    const [ro, ri] = await Promise.all([
      fetch('/api/xui/outbounds',{method:'POST',headers:hdrs(),body}),
      fetch('/api/xui/inbounds', {method:'POST',headers:hdrs(),body})
    ]);
    const [do_, di] = await Promise.all([ro.json(), ri.json()]);

    // outbounds
    const port = document.getElementById('xo').value || '1111';
    document.getElementById('upTag').textContent = 'inbound-127.0.0.1:' + port;
    renderList('outList', do_.outbounds||[], 'out', item=>{
      selOutTag = item.tag;
      document.getElementById('selOut').value = item.tag + ' (' + item.protocol + ')';
    }, item=>item.tag+' '+item.protocol);

    // inbounds
    renderList('inList', di.inbounds||[], 'in', item=>{
      selInTag = item.tag;
      document.getElementById('selIn').value = item.tag + ' (' + item.remark + ')';
    }, item=>item.tag+' '+item.remark);

    const tot = (do_.outbounds?.length||0) + (di.inbounds?.length||0);
    if(tot > 0) show('xs','ok','✅ '+tot+' آیتم دریافت شد');
    else show('xs','er','❌ چیزی پیدا نشد');
  } catch { show('xs','er','❌ خطا'); }
  btn.disabled = false;
}

function renderList(containerId, items, type, onSelect, label){
  const box = document.getElementById(containerId);
  box.innerHTML = '';
  if(!items.length){
    box.innerHTML = '<div style="padding:12px;color:var(--dm);font-size:9px;text-align:center">موردی پیدا نشد</div>';
    return;
  }
  items.forEach((item, i) => {
    const el = document.createElement('div');
    el.className = 'ob-item';
    const tag = type==='out' ? item.tag : item.tag;
    const proto = type==='out' ? item.protocol : item.remark;
    el.innerHTML = '<span class="ob-tag">' + tag + '</span>'
      + '<span class="ob-pro">' + proto + '</span>';
    el.style.animationDelay = (i * .03) + 's';
    el.onclick = () => {
      box.querySelectorAll('.ob-item').forEach(e=>{ e.classList.remove('sel'); e.querySelector('.ob-tag').classList.remove('sel-glow'); });
      el.classList.add('sel');
      el.querySelector('.ob-tag').classList.add('sel-glow');
      onSelect(item);
    };
    box.appendChild(el);
  });
}

async function applyUpRoute(){
  if(!selOutTag){ show('rs1','er','⚠ ابتدا outbound رو انتخاب کن'); return; }
  const port = document.getElementById('xo').value || '1111';
  const inTag = 'inbound-127.0.0.1:' + port;
  show('rs1','if','در حال اعمال routing...',0);
  try{
    const body = {...xuiBody(), inbound_tag:inTag, outbound_tag:selOutTag};
    const r = await fetch('/api/xui/routing',{method:'POST',headers:hdrs(),body:JSON.stringify(body)});
    const d = await r.json();
    show('rs1', d.ok?'ok':'er', d.ok?'✅ '+d.msg:'❌ '+d.msg);
  } catch { show('rs1','er','❌ خطا'); }
}

async function applySocksRoute(){
  if(!selInTag){ show('rs2','er','⚠ ابتدا inbound رو انتخاب کن'); return; }
  // outbound socks که به 127.0.0.1:7070 وصله
  // این باید از قبل در 3x-ui وجود داشته باشه
  show('rs2','if','در حال اعمال routing...',0);
  try{
    // باید outbound با socks به 127.0.0.1:7070 اول بسازیم اگه نبود
    const body = {...xuiBody(), inbound_tag:selInTag, outbound_tag:'qs-socks-out'};
    const r = await fetch('/api/xui/routing',{method:'POST',headers:hdrs(),body:JSON.stringify(body)});
    const d = await r.json();
    show('rs2', d.ok?'ok':'er', d.ok?'✅ '+d.msg:'❌ '+d.msg);
  } catch { show('rs2','er','❌ خطا'); }
}

// ── Config ────────────────────────────────────────────────────────────────────
function onTr(){
  document.getElementById('f-obfs-wrap').style.display =
    document.getElementById('f-tr').value === 'obfs' ? 'flex' : 'none';
}

function setVal(id, v){ const e=document.getElementById(id); if(e&&v!=null)e.value=v||''; }
function setSel(id, v){
  const e = document.getElementById(id);
  if(!e||!v) return;
  for(let i=0;i<e.options.length;i++){
    if(e.options[i].value===v){ e.selectedIndex=i; break; }
  }
}

async function loadCfg(){
  try{
    const r = await fetch('/api/config/load',{headers:{Authorization:'Bearer '+tok}});
    const d = await r.json();
    if(!d.ok) return;
    const c = d.config || {};
    setVal('f-srv', c.server_addr);
    setVal('f-ip',  c.my_public_ip);
    setVal('f-prx', c.upload_proxy);
    setVal('f-sk',  c.local_socks);
    setVal('f-dlp', c.download_port);
    setVal('f-ms',  c.max_streams);
    setSel('f-tr',  c.transport_mode||'udp');
    setVal('f-ok',  c.obfs_key);
    onTr();
    setVal('f-da',  c.dashboard_addr);
    setVal('f-dk',  c.dashboard_key);
    setVal('f-met', c.metrics_addr);
    document.getElementById('f-vb').checked = !!c.verbose;
    if(c.xui){
      setVal('f-xu',  c.xui.panel_url);
      setVal('f-xn',  c.xui.username);
      setVal('f-xpo', c.xui.inbound_port);
      // Setup تب هم پر کن
      const xu=document.getElementById('xu'); if(xu&&c.xui.panel_url)xu.value=c.xui.panel_url;
      const xn=document.getElementById('xn'); if(xn&&c.xui.username)xn.value=c.xui.username;
      const xo=document.getElementById('xo'); if(xo&&c.xui.inbound_port)xo.value=c.xui.inbound_port;
    }
  } catch {}
}

async function saveCfg(){
  const btn = document.getElementById('saveBtn');
  btn.disabled = true;
  show('cfg-st','if','در حال ذخیره و restart...',0);
  try{
    const r0 = await fetch('/api/config/load',{headers:{Authorization:'Bearer '+tok}});
    const d0 = await r0.json();
    const cfg = d0.ok ? d0.config : {};

    cfg.server_addr    = document.getElementById('f-srv').value;
    cfg.my_public_ip   = document.getElementById('f-ip').value;
    cfg.upload_proxy   = document.getElementById('f-prx').value;
    cfg.local_socks    = document.getElementById('f-sk').value;
    cfg.download_port  = +document.getElementById('f-dlp').value || 8000;
    cfg.max_streams    = +document.getElementById('f-ms').value  || 512;
    cfg.transport_mode = document.getElementById('f-tr').value;
    cfg.obfs_key       = document.getElementById('f-ok').value;
    cfg.dashboard_addr = document.getElementById('f-da').value;
    cfg.dashboard_key  = document.getElementById('f-dk').value;
    cfg.metrics_addr   = document.getElementById('f-met').value;
    cfg.verbose        = document.getElementById('f-vb').checked;
    if(!cfg.xui) cfg.xui = {};
    cfg.xui.panel_url    = document.getElementById('f-xu').value;
    cfg.xui.username     = document.getElementById('f-xn').value;
    cfg.xui.password     = document.getElementById('f-xp').value || cfg.xui.password || '';
    cfg.xui.inbound_port = +document.getElementById('f-xpo').value || 1111;

    const r = await fetch('/api/config/save',{
      method:'POST',headers:hdrs(),body:JSON.stringify(cfg)
    });
    const d = await r.json();
    if(!d.ok){ show('cfg-st','er','❌ '+d.msg); btn.disabled=false; return; }
    show('cfg-st','ok','✅ ذخیره شد — در حال restart...',10000);
    setTimeout(async()=>{
      try{ await fetch('/api/restart',{method:'POST',headers:{Authorization:'Bearer '+tok}}); } catch{}
      // صبر کن و reload کن
      setTimeout(()=>location.reload(), 3000);
    }, 700);
  } catch(e){
    show('cfg-st','er','❌ خطا: '+e.message);
    btn.disabled = false;
  }
}
</script>
</body>
</html>
`
