// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const defaultIPRateLimiterMaxBuckets = 128

type IPRateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*ipBucket
	rate       rate.Limit
	burst      int
	maxBuckets int
	gcEvery    int
	idleExpiry time.Duration
	calls      int
	now        func() time.Time
}

type ipBucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func NewIPRateLimiter(r rate.Limit, burst, maxBuckets int) *IPRateLimiter {
	if r > 0 && burst < 1 {
		burst = 1
	}
	if r > 0 && maxBuckets < 1 {
		maxBuckets = defaultIPRateLimiterMaxBuckets
	}
	return &IPRateLimiter{
		buckets:    make(map[string]*ipBucket),
		rate:       r,
		burst:      burst,
		maxBuckets: maxBuckets,
		gcEvery:    256,
		idleExpiry: ipRateLimiterIdleExpiry(r, burst),
		now:        time.Now,
	}
}

func ipRateLimiterIdleExpiry(r rate.Limit, burst int) time.Duration {
	if r <= 0 || burst < 1 {
		return 10 * time.Minute
	}

	seconds := math.Ceil(float64(burst) / float64(r))
	d := time.Duration(seconds) * time.Second
	if d < time.Minute {
		return time.Minute
	}
	if d > 10*time.Minute {
		return 10 * time.Minute
	}
	return d
}

func (l *IPRateLimiter) Allow(ip string) bool {
	if l == nil || l.rate <= 0 || ip == "" {
		return true
	}

	l.mu.Lock()
	b, ok := l.buckets[ip]
	if !ok {
		if l.maxBuckets > 0 && len(l.buckets) >= l.maxBuckets {
			l.gcLocked()
		}
		if l.maxBuckets > 0 && len(l.buckets) >= l.maxBuckets {
			l.mu.Unlock()
			return false
		}
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

func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if !l.Allow(ip) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ClientIP(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
