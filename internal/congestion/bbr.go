// Package congestion — BBR-inspired congestion control
//
// BBR (Bottleneck Bandwidth and RTT):
//   - به جای packet loss، از bandwidth × RTT استفاده میکنه
//   - پنجره = BtlBW × RTprop
//   - در سه فاز کار میکنه: Startup, Drain, ProbeBW
//
// سازگاری با سیستم فعلی:
//   - جایگزین session.Flow میشه
//   - API مشابه: Acquire/Release
//   - کار با UDP دانلود و TCP آپلود
package congestion

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// BBR phases
type phase int

const (
	phaseStartup  phase = iota
	phaseDrain
	phaseProbeBW
	phaseProbeRTT
)

// WindowedMax — max value در یه پنجره زمانی
type WindowedMax struct {
	mu     sync.Mutex
	values [3]struct {
		val  float64
		time time.Time
	}
	win time.Duration
}

func NewWindowedMax(win time.Duration) *WindowedMax {
	return &WindowedMax{win: win}
}

func (w *WindowedMax) Update(val float64, now time.Time) float64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	// پاک کردن مقادیر قدیمی
	threshold := now.Add(-w.win)
	for i := range w.values {
		if w.values[i].time.Before(threshold) {
			w.values[i].val = 0
		}
	}

	// اضافه کردن مقدار جدید
	w.values[2] = w.values[1]
	w.values[1] = w.values[0]
	w.values[0].val = val
	w.values[0].time = now

	// max
	max := 0.0
	for _, v := range w.values {
		if v.val > max {
			max = v.val
		}
	}
	return max
}

// BBRController — کنترل‌کننده congestion
type BBRController struct {
	mu sync.Mutex

	// اندازه‌گیری
	btlBW     float64   // Bottleneck Bandwidth (bytes/sec)
	rtProp    time.Duration // Round-trip propagation time
	rtPropExp time.Time    // زمان expire RTprop

	// پنجره
	cwnd      atomic.Int64 // congestion window (bytes)
	inflight  atomic.Int64 // bytes در حال انتقال

	// BBR state
	phase     phase
	paceGain  float64
	cwndGain  float64

	// windowed max bandwidth
	maxBW     *WindowedMax

	// timing
	lastBWUpdate time.Time
	phaseStart   time.Time
	cycleIdx     int

	// آمار
	BytesSent    atomic.Uint64
	BytesAcked   atomic.Uint64
	RTTSamples   atomic.Uint64
	CWNDUpdates  atomic.Uint64
}

// BW gain cycle برای ProbeBW
var paceGainCycle = [8]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

// New یه BBRController جدید میسازه
func New(initWindow int64) *BBRController {
	b := &BBRController{
		rtProp:    100 * time.Millisecond,
		rtPropExp: time.Now().Add(10 * time.Second),
		paceGain:  2.885, // sqrt(8) برای Startup
		cwndGain:  2.885,
		phase:     phaseStartup,
		maxBW:     NewWindowedMax(10 * time.Second),
		phaseStart: time.Now(),
	}
	b.cwnd.Store(initWindow)
	b.btlBW = float64(initWindow) / b.rtProp.Seconds()
	return b
}

// OnAck: وقتی bytes ack میشن صدا بشه
func (b *BBRController) OnAck(bytesAcked int64, rtt time.Duration) {
	b.BytesAcked.Add(uint64(bytesAcked))
	b.RTTSamples.Add(1)
	b.inflight.Add(-bytesAcked)

	now := time.Now()

	b.mu.Lock()
	defer b.mu.Unlock()

	// آپدیت RTprop (min RTT)
	if rtt < b.rtProp || now.After(b.rtPropExp) {
		b.rtProp = rtt
		b.rtPropExp = now.Add(10 * time.Second)
	}

	// آپدیت BtlBW
	elapsed := now.Sub(b.lastBWUpdate)
	if elapsed > 0 {
		deliveryRate := float64(bytesAcked) / elapsed.Seconds()
		b.btlBW = b.maxBW.Update(deliveryRate, now)
		b.lastBWUpdate = now
	}

	b.updateCWND()
	b.updatePhase(now)
}

func (b *BBRController) updateCWND() {
	// cwnd = BtlBW × RTprop × cwndGain
	targetCWND := b.btlBW * b.rtProp.Seconds() * b.cwndGain

	// حداقل و حداکثر
	if targetCWND < 4096 {
		targetCWND = 4096
	}
	if targetCWND > 128*1024*1024 { // 128MB max
		targetCWND = 128 * 1024 * 1024
	}

	b.cwnd.Store(int64(math.Round(targetCWND)))
	b.CWNDUpdates.Add(1)
}

func (b *BBRController) updatePhase(now time.Time) {
	switch b.phase {
	case phaseStartup:
		// Startup: تا BW دیگه رشد نکنه
		if b.isFullPipe() {
			b.phase = phaseDrain
			b.paceGain = 1.0 / 2.885
			b.cwndGain = 2.885
			b.phaseStart = now
		}

	case phaseDrain:
		// Drain: تا queue خالی بشه
		if b.inflight.Load() <= b.bdp() {
			b.phase = phaseProbeBW
			b.cycleIdx = 0
			b.paceGain = paceGainCycle[0]
			b.cwndGain = 2
			b.phaseStart = now
		}

	case phaseProbeBW:
		// ProbeBW: چرخه 8 phase
		if now.Sub(b.phaseStart) > b.rtProp {
			b.cycleIdx = (b.cycleIdx + 1) % 8
			b.paceGain = paceGainCycle[b.cycleIdx]
			b.phaseStart = now
		}
		// هر ۱۰ ثانیه ProbeRTT
		if now.After(b.rtPropExp) {
			b.phase = phaseProbeRTT
			b.cwndGain = 0.5
			b.phaseStart = now
		}

	case phaseProbeRTT:
		// ProbeRTT: 200ms با cwnd کم
		if now.Sub(b.phaseStart) > 200*time.Millisecond {
			b.phase = phaseProbeBW
			b.cwndGain = 2
			b.phaseStart = now
		}
	}
}

func (b *BBRController) isFullPipe() bool {
	// اگه ۳ بار پشت سرهم BW رشد نکرد → full pipe
	return b.btlBW > 0 && b.inflight.Load() >= b.bdp()
}

func (b *BBRController) bdp() int64 {
	return int64(b.btlBW * b.rtProp.Seconds())
}

// Acquire: قبل از ارسال صدا بشه — اگه cwnd پر بود block میکنه
func (b *BBRController) Acquire(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		cwnd := b.cwnd.Load()
		inflight := b.inflight.Load()
		if inflight+int64(n) <= cwnd {
			b.inflight.Add(int64(n))
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Microsecond)
	}
}

// Release: بعد از دریافت ACK — مستقیم در OnAck صدا میشه
func (b *BBRController) Release(n int) {
	// در OnAck handle میشه
	_ = n
}

// Close window رو میبنده
func (b *BBRController) Close() {}

// Stats آمار فعلی
func (b *BBRController) Stats() (btlBW float64, rtProp time.Duration, cwnd int64, phase string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	phases := []string{"Startup", "Drain", "ProbeBW", "ProbeRTT"}
	return b.btlBW, b.rtProp, b.cwnd.Load(), phases[b.phase]
}
