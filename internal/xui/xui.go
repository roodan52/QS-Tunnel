// Package xui — 3x-ui panel integration
//
// Endpoints طبق Wiki رسمی:
//   POST /login
//   GET  /panel/api/inbounds/list
//   POST /panel/api/inbounds/add
//   GET  /panel/api/server/getConfigJson
//   POST /panel/api/server/restartXrayService
package xui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	PanelURL    string `json:"panel_url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	InboundPort int    `json:"inbound_port"`
	InboundTag  string `json:"inbound_tag"`
	SocksPort   int    `json:"socks_port"`
}

func DefaultConfig() Config {
	return Config{
		PanelURL:    "http://127.0.0.1:2053",
		Username:    "admin",
		InboundPort: 1111,
		InboundTag:  "qs-upload",
		SocksPort:   7070,
	}
}

type Inbound struct {
	ID       int    `json:"id"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Listen   string `json:"listen"`
	Enable   bool   `json:"enable"`
	Tag      string `json:"tag"`
}

type Outbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
}

type Client struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 10 * time.Second, Jar: jar},
	}
}

func (c *Client) Setup() error {
	if err := c.login(); err != nil {
		return fmt.Errorf("لاگین: %w", err)
	}
	exists, id, _ := c.findInbound(c.cfg.InboundTag)
	if exists {
		return fmt.Errorf("inbound '%s' قبلاً وجود داره (id=%d)", c.cfg.InboundTag, id)
	}
	return c.createMixedInbound(c.cfg.InboundPort, c.cfg.InboundTag, "127.0.0.1")
}

func (c *Client) Status() (string, error) {
	if err := c.login(); err != nil { return "", err }
	exists, id, _ := c.findInbound(c.cfg.InboundTag)
	if exists {
		return fmt.Sprintf("inbound '%s' فعال (id=%d, port=%d)", c.cfg.InboundTag, id, c.cfg.InboundPort), nil
	}
	return fmt.Sprintf("inbound '%s' وجود ندارد", c.cfg.InboundTag), nil
}

// ListOutbounds — از getConfigJson که config.json کامل xray رو برمیگردونه
func (c *Client) ListOutbounds() ([]Outbound, error) {
	if err := c.login(); err != nil {
		return nil, fmt.Errorf("لاگین: %w", err)
	}
	xrayCfg, err := c.getXrayConfig()
	if err != nil {
		return nil, err
	}
	rawObs, ok := xrayCfg["outbounds"].([]interface{})
	if !ok || len(rawObs) == 0 {
		return nil, errors.New("outbounds در config پیدا نشد")
	}
	var result []Outbound
	for _, o := range rawObs {
		m, ok := o.(map[string]interface{})
		if !ok { continue }
		tag := str(m["tag"])
		if tag == "" { continue }
		result = append(result, Outbound{Tag: tag, Protocol: str(m["protocol"])})
	}
	return result, nil
}

// SetupRouting — routing rule میسازه و xray رو restart میکنه
func (c *Client) SetupRouting(inboundTag, outboundTag string) error {
	if err := c.login(); err != nil { return err }

	xrayCfg, err := c.getXrayConfig()
	if err != nil { return err }

	// routing section
	routing, _ := xrayCfg["routing"].(map[string]interface{})
	if routing == nil {
		routing = map[string]interface{}{"domainStrategy": "AsIs", "rules": []interface{}{}}
		xrayCfg["routing"] = routing
	}
	rules, _ := routing["rules"].([]interface{})

	// چک duplicate
	for _, r := range rules {
		rm, ok := r.(map[string]interface{})
		if !ok { continue }
		if str(rm["outboundTag"]) == outboundTag {
			if tags, ok := rm["inboundTag"].([]interface{}); ok {
				for _, t := range tags {
					if str(t) == inboundTag { return nil }
				}
			}
		}
	}

	// اضافه کردن rule
	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"inboundTag":  []string{inboundTag},
		"outboundTag": outboundTag,
	})
	routing["rules"] = rules

	// ذخیره از طریق /panel/xray/update (endpoint رسمی 3x-ui)
	return c.saveXrayConfig(xrayCfg)
}

// saveXrayConfig — POST /panel/xray/update
// باید application/x-www-form-urlencoded باشه:
// xraySetting={json}&outboundTestUrl=https://...
func (c *Client) saveXrayConfig(xrayCfg map[string]interface{}) error {
	base := strings.TrimRight(c.cfg.PanelURL, "/")

	cfgBytes, err := json.Marshal(xrayCfg)
	if err != nil { return fmt.Errorf("marshal: %w", err) }

	// form-encoded — دقیقاً مثل browser
	formData := url.Values{}
	formData.Set("xraySetting", string(cfgBytes))
	formData.Set("outboundTestUrl", "https://www.google.com/generate_204")

	req, _ := http.NewRequest("POST", base+"/panel/xray/update",
		strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil { return fmt.Errorf("HTTP: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return errors.New("/panel/xray/update پیدا نشد")
	}
	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if ok, _ := result["success"].(bool); !ok {
		msg, _ := result["msg"].(string)
		return fmt.Errorf("save: %s", msg)
	}
	return nil
}

// ─── Private ─────────────────────────────────────────────────────────────────

func (c *Client) login() error {
	base := strings.TrimRight(c.cfg.PanelURL, "/")
	body, _ := json.Marshal(map[string]string{"username": c.cfg.Username, "password": c.cfg.Password})
	req, _ := http.NewRequest("POST", base+"/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil { return fmt.Errorf("اتصال: %w", err) }
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if ok, _ := result["success"].(bool); !ok {
		msg, _ := result["msg"].(string)
		if msg == "" { msg = "اطلاعات لاگین اشتباه" }
		return errors.New(msg)
	}
	return nil
}

// getXrayConfig — config.json فعلی رو از API میگیره
func (c *Client) getXrayConfig() (map[string]interface{}, error) {
	base := strings.TrimRight(c.cfg.PanelURL, "/")
	resp, err := c.http.Get(base + "/panel/api/server/getConfigJson")
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, errors.New("getConfigJson 404 — نسخه 3x-ui رو آپدیت کن")
	}
	body, _ := io.ReadAll(resp.Body)

	// parse — handle همه فرمت‌ها
	var top map[string]interface{}
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	// اگه مستقیم xray config هست
	if _, ok := top["outbounds"]; ok { return top, nil }
	if _, ok := top["inbounds"]; ok  { return top, nil }

	// wrapped
	if obj, ok := top["obj"]; ok {
		switch v := obj.(type) {
		case map[string]interface{}: return v, nil
		case string:
			var inner map[string]interface{}
			if err := json.Unmarshal([]byte(v), &inner); err == nil { return inner, nil }
		}
	}
	return top, nil
}

func (c *Client) listInbounds() ([]Inbound, error) {
	base := strings.TrimRight(c.cfg.PanelURL, "/")
	resp, err := c.http.Get(base + "/panel/api/inbounds/list")
	if err != nil { return nil, err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	obj, _ := result["obj"].([]interface{})
	var inbounds []Inbound
	for _, item := range obj {
		m, ok := item.(map[string]interface{})
		if !ok { continue }
		ib := Inbound{
			ID: int(num(m["id"])), Remark: str(m["remark"]),
			Protocol: str(m["protocol"]), Port: int(num(m["port"])),
			Listen: str(m["listen"]), Enable: bool_(m["enable"]),
		}
		listen := ib.Listen
		if listen == "" || listen == "0.0.0.0" { ib.Tag = fmt.Sprintf("inbound-%d", ib.Port) } else { ib.Tag = fmt.Sprintf("inbound-%s:%d", listen, ib.Port) }
		inbounds = append(inbounds, ib)
	}
	return inbounds, nil
}

func (c *Client) findInbound(remark string) (bool, int, error) {
	inbounds, err := c.listInbounds()
	if err != nil { return false, 0, err }
	for _, ib := range inbounds { if ib.Remark == remark { return true, ib.ID, nil } }
	return false, 0, nil
}

func (c *Client) createMixedInbound(port int, remark, listen string) error {
	base := strings.TrimRight(c.cfg.PanelURL, "/")
	settings, _ := json.Marshal(map[string]interface{}{"auth": "noauth", "accounts": []interface{}{}, "udp": false, "ip": listen})
	stream, _ := json.Marshal(map[string]interface{}{"network": "tcp", "security": "none", "tcpSettings": map[string]interface{}{"acceptProxyProtocol": false, "header": map[string]interface{}{"type": "none"}}})
	sniff, _ := json.Marshal(map[string]interface{}{"enabled": false, "destOverride": []string{}})
	alloc, _ := json.Marshal(map[string]interface{}{"strategy": "always", "refresh": 5, "concurrency": 3})
	payload, _ := json.Marshal(map[string]interface{}{
		"remark": remark, "enable": true, "protocol": "mixed",
		"port": port, "listen": listen, "expiryTime": 0, "total": 0,
		"settings": string(settings), "streamSettings": string(stream),
		"sniffing": string(sniff), "allocate": string(alloc),
	})
	req, _ := http.NewRequest("POST", base+"/panel/api/inbounds/add", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if ok, _ := result["success"].(bool); !ok {
		msg, _ := result["msg"].(string)
		return fmt.Errorf("API: %s", msg)
	}
	return nil
}

func str(v interface{}) string  { s, _ := v.(string); return s }
func num(v interface{}) float64 { n, _ := v.(float64); return n }
func bool_(v interface{}) bool  { b, _ := v.(bool); return b }

// ListInbounds همه inbound های پنل رو برمیگردونه
func (c *Client) ListInbounds() ([]Inbound, error) {
	if err := c.login(); err != nil { return nil, err }
	return c.listInbounds()
}
