// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestIPRateLimiter_AllowsBurstThenLimits(t *testing.T) {
	l := NewIPRateLimiter(1.0, 3, 0)

	for i := 0; i < 3; i++ {
		assert.True(t, l.Allow("1.2.3.4"), "first %d should fit in burst", i+1)
	}
	assert.False(t, l.Allow("1.2.3.4"), "burst exhausted; 4th must be rejected")
}

func TestIPRateLimiter_PerIPIsolated(t *testing.T) {
	l := NewIPRateLimiter(0.1, 1, 0)

	assert.True(t, l.Allow("1.1.1.1"))
	assert.False(t, l.Allow("1.1.1.1"))
	assert.True(t, l.Allow("2.2.2.2"), "second IP gets its own bucket")
	assert.True(t, l.Allow("3.3.3.3"))
}

func TestIPRateLimiter_DisabledWhenRateZero(t *testing.T) {
	l := NewIPRateLimiter(0, 1, 0)
	for i := 0; i < 100; i++ {
		assert.True(t, l.Allow("1.1.1.1"))
	}
}

func TestIPRateLimiter_NilSafeAllow(t *testing.T) {
	var l *IPRateLimiter
	assert.True(t, l.Allow("1.1.1.1"), "nil receiver must default-allow")
}

func TestIPRateLimiter_EmptyIPDefaultsAllow(t *testing.T) {
	l := NewIPRateLimiter(1.0, 1, 0)
	assert.True(t, l.Allow(""))
	assert.True(t, l.Allow(""), "empty IP never consumes a bucket")
}

func TestIPRateLimiter_GCEvictsIdleBuckets(t *testing.T) {
	l := NewIPRateLimiter(1.0, 1, 0)
	l.gcEvery = 1
	l.idleExpiry = time.Millisecond

	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }

	l.Allow("1.1.1.1")
	assert.Len(t, l.buckets, 1)

	now = now.Add(time.Second)
	l.Allow("2.2.2.2")
	assert.Len(t, l.buckets, 1, "stale bucket evicted; only 2.2.2.2 remains")
	_, has := l.buckets["1.1.1.1"]
	assert.False(t, has)
	_, has = l.buckets["2.2.2.2"]
	assert.True(t, has)
}

func TestIPRateLimiter_Middleware_AllowsThenLimits(t *testing.T) {
	l := NewIPRateLimiter(rate.Limit(1.0), 2, 0)
	called := 0
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))

	doReq := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/challenge", nil)
		r.RemoteAddr = "5.6.7.8:54321"
		h.ServeHTTP(w, r)
		return w
	}

	w1 := doReq()
	w2 := doReq()
	w3 := doReq()

	assert.Equal(t, http.StatusNoContent, w1.Code)
	assert.Equal(t, http.StatusNoContent, w2.Code)
	assert.Equal(t, http.StatusTooManyRequests, w3.Code)
	assert.Equal(t, 2, called, "wrapped handler must not be called for the rejected request")
}

func TestIPRateLimiter_Middleware_DistinctIPsBypassEachOther(t *testing.T) {
	l := NewIPRateLimiter(rate.Limit(0.1), 1, 0)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	mk := func(addr string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/challenge", nil)
		r.RemoteAddr = addr
		h.ServeHTTP(w, r)
		return w
	}

	assert.Equal(t, http.StatusNoContent, mk("9.9.9.9:1").Code)
	assert.Equal(t, http.StatusTooManyRequests, mk("9.9.9.9:2").Code, "same IP, second hit rejected")
	assert.Equal(t, http.StatusNoContent, mk("8.8.8.8:1").Code, "different IP, fresh bucket")
}

func TestIPRateLimiter_ClampsBurstWhenEnabled(t *testing.T) {
	l := NewIPRateLimiter(rate.Limit(1.0), 0, 0)

	assert.True(t, l.Allow("1.1.1.1"))
	assert.False(t, l.Allow("1.1.1.1"))
}

func TestIPRateLimiter_MaxBucketsRejectsNewIP(t *testing.T) {
	l := NewIPRateLimiter(rate.Limit(1.0), 1, 2)

	assert.True(t, l.Allow("1.1.1.1"))
	assert.True(t, l.Allow("2.2.2.2"))
	assert.False(t, l.Allow("3.3.3.3"))
	assert.Len(t, l.buckets, 2)
}

func TestIPRateLimiter_MaxBucketsSweepsBeforeRejecting(t *testing.T) {
	l := NewIPRateLimiter(rate.Limit(1.0), 1, 1)
	l.idleExpiry = time.Millisecond

	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }

	assert.True(t, l.Allow("1.1.1.1"))
	now = now.Add(time.Second)
	assert.True(t, l.Allow("2.2.2.2"))
	assert.Len(t, l.buckets, 1)
	_, has := l.buckets["2.2.2.2"]
	assert.True(t, has)
}

func TestClientIP_StripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.7:55321"
	assert.Equal(t, "203.0.113.7", ClientIP(r))
}

func TestClientIP_TolerantOfBareIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.7"
	assert.Equal(t, "203.0.113.7", ClientIP(r))
}

func TestClientIP_NilOrEmpty(t *testing.T) {
	assert.Equal(t, "", ClientIP(nil))
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = ""
	assert.Equal(t, "", ClientIP(r))
}
