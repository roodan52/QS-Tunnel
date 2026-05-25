package batchsend

import "time"

// nanoTimer یه timer بهینه برای interval کوتاه
type nanoTimer struct {
	t *time.Timer
	c <-chan time.Time
}

func newNanoTimer(ns int) *nanoTimer {
	t := time.NewTimer(time.Duration(ns))
	return &nanoTimer{t: t, c: t.C}
}

func (nt *nanoTimer) C() <-chan time.Time { return nt.c }
func (nt *nanoTimer) stop()              { nt.t.Stop() }
func (nt *nanoTimer) reset(ns int) {
	if !nt.t.Stop() {
		select {
		case <-nt.t.C:
		default:
		}
	}
	nt.t.Reset(time.Duration(ns))
}
