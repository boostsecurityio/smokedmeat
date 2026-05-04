// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPRateLimiter is a per-source-IP token-bucket limiter. It is used to gate
// the unauthenticated /auth/challenge endpoint so an attacker cannot spam
// CreateChallenge from a single source — even before the global
// MaxPendingChallenges cap fires, per-IP throttling makes the cost of a
// memory-exhaustion attack proportional to how many distinct source IPs the
// attacker controls.
//
// The limiter is intentionally narrow: one bucket per remote IP, GC'd lazily
// when an entry has been idle longer than its bucket would take to fully
// refill. There is no cross-instance coordination — operators running
// multiple Kitchen instances behind a load balancer should configure the
// limit per-instance accordingly.
type IPRateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*ipBucket
	rate       rate.Limit
	burst      int
	gcEvery    int           // GC sweep cadence (every N Allow calls)
	idleExpiry time.Duration // bucket evicted after this much idle time
	calls      int           // counter for GC cadence; cheap, no atomics needed
	now        func() time.Time
}

type ipBucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// NewIPRateLimiter returns a limiter that allows `r` requests per second per
// IP with a burst of `burst`. A zero or negative `r` disables limiting.
func NewIPRateLimiter(r rate.Limit, burst int) *IPRateLimiter {
	return &IPRateLimiter{
		buckets:    make(map[string]*ipBucket),
		rate:       r,
		burst:      burst,
		gcEvery:    256,
		idleExpiry: 10 * time.Minute,
		now:        time.Now,
	}
}

// Allow reports whether the request from the given IP is allowed under the
// limiter. An empty IP (e.g. unparseable RemoteAddr) is allowed — the caller
// is responsible for deciding whether that should be treated as a failure
// case; here we err on the side of availability.
func (l *IPRateLimiter) Allow(ip string) bool {
	if l == nil || l.rate <= 0 || ip == "" {
		return true
	}

	l.mu.Lock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &ipBucket{lim: rate.NewLimiter(l.rate, l.burst)}
		l.buckets[ip] = b
	}
	b.lastSeen = l.now()
	allowed := b.lim.Allow()

	l.calls++
	if l.calls >= l.gcEvery {
		l.calls = 0
		l.gcLocked()
	}
	l.mu.Unlock()

	return allowed
}

func (l *IPRateLimiter) gcLocked() {
	cutoff := l.now().Add(-l.idleExpiry)
	for ip, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
}

// Middleware wraps an http.Handler with per-source-IP rate limiting. On a
// rejection it writes a `429 Too Many Requests` response with a
// `Retry-After` hint (in seconds) and short-circuits before the wrapped
// handler runs.
func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if !l.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP returns the source IP for a request as a bucket key. We look at
// `RemoteAddr` only — `X-Forwarded-For` is intentionally NOT trusted by
// default because the kitchen does not know whether it sits behind a
// trusted reverse proxy. Operators terminating TLS in front of the kitchen
// should configure their proxy to overwrite RemoteAddr (e.g. via PROXY
// protocol or the equivalent), or wrap the mux with their own header-aware
// middleware. Returning an empty string causes Allow() to default-allow.
func ClientIP(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Some test paths set RemoteAddr to a bare IP; tolerate that.
		return r.RemoteAddr
	}
	return host
}
