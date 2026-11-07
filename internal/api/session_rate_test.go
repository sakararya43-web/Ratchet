package api

import (
	"fmt"
	"testing"
	"time"
)

func TestLoginLimiterBoundsUnknownPeersAndSeparatesIPv6Hosts(t *testing.T) {
	s := &Sessions{attempts: map[[32]byte]rateEntry{}}
	now := time.Now()
	for range 5 {
		if !s.allowLogin("[2001:db8::1]:1234", now) {
			t.Fatal("valid attempt refused")
		}
	}
	if s.allowLogin("[2001:db8::1]:5678", now) {
		t.Fatal("changing the source port bypassed the rate limit")
	}
	if !s.allowLogin("[2001:db8::2]:1234", now) {
		t.Fatal("independent IPv6 hosts share a login limit")
	}
	for i := range 12000 {
		s.allowLogin(fmt.Sprintf("peer-%d:1234", i), now)
	}
	if len(s.attempts) > 10000 || s.allowLogin("another-peer:1234", now) {
		t.Fatal("unknown peers grew or bypassed a full rate-limit map")
	}
	if !s.allowLogin("another-peer:1234", now.Add(2*time.Minute)) {
		t.Fatal("expired buckets prevented recovery")
	}
}
