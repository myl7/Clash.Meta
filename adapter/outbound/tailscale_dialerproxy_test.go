//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type mapTunnel struct {
	C.Tunnel
	mu sync.Mutex
	m  map[string]C.Proxy
}

func (t *mapTunnel) Proxies() map[string]C.Proxy {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m
}

func (t *mapTunnel) install(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[name] = nil
}

func withShrunkDialerProxyTimings(t *testing.T) {
	t.Helper()
	oldTick, oldTimeout := dialerProxyInstallTick, dialerProxyInstallTimeout
	dialerProxyInstallTick = time.Millisecond
	dialerProxyInstallTimeout = 80 * time.Millisecond
	t.Cleanup(func() {
		dialerProxyInstallTick, dialerProxyInstallTimeout = oldTick, oldTimeout
	})
}

func TestWaitForDialerProxyReturnsOnceInstalled(t *testing.T) {
	withShrunkDialerProxyTimings(t)
	tun := &mapTunnel{m: map[string]C.Proxy{}}
	go func() {
		time.Sleep(30 * time.Millisecond)
		tun.install("ts-underlay")
	}()
	start := time.Now()
	waitForDialerProxy(context.Background(), tun, "ts-underlay")
	if elapsed := time.Since(start); elapsed >= dialerProxyInstallTimeout {
		t.Fatalf("waitForDialerProxy waited the full timeout (%v); the install was not observed", elapsed)
	}
}

func TestWaitForDialerProxyIsBoundedWhenNeverInstalled(t *testing.T) {
	withShrunkDialerProxyTimings(t)
	start := time.Now()
	waitForDialerProxy(context.Background(), &mapTunnel{m: map[string]C.Proxy{}}, "ts-underlay")
	if elapsed := time.Since(start); elapsed >= 2*dialerProxyInstallTimeout {
		t.Fatalf("waitForDialerProxy overran its timeout: %v", elapsed)
	}
}

func TestWaitForDialerProxyEndsOnContextCancel(t *testing.T) {
	withShrunkDialerProxyTimings(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	waitForDialerProxy(ctx, &mapTunnel{m: map[string]C.Proxy{}}, "ts-underlay")
	if elapsed := time.Since(start); elapsed >= dialerProxyInstallTimeout {
		t.Fatalf("waitForDialerProxy ignored the context cancel: %v", elapsed)
	}
}

func TestWaitForDialerProxyReturnsWithoutTunnel(t *testing.T) {
	withShrunkDialerProxyTimings(t)
	start := time.Now()
	waitForDialerProxy(context.Background(), nil, "ts-underlay")
	if elapsed := time.Since(start); elapsed >= dialerProxyInstallTimeout {
		t.Fatalf("a nil tunnel must not wait: %v", elapsed)
	}
}
