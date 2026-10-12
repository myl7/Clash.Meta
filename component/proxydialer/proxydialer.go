package proxydialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type proxyDialer struct {
	proxy     C.ProxyAdapter
	statistic bool
}

func New(proxy C.ProxyAdapter, statistic bool) C.Dialer {
	return proxyDialer{proxy: proxy, statistic: statistic}
}

func (p proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	currentMeta := &C.Metadata{Type: C.INNER}
	if err := currentMeta.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	if strings.Contains(network, "udp") { // using in wireguard outbound
		pc, err := p.listenPacket(ctx, currentMeta)
		if err != nil {
			return nil, err
		}
		if !currentMeta.Resolved() { // should not happen, maybe by a wrongly implemented proxy, but we can handle this (:
			err = pc.ResolveUDP(ctx, currentMeta)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
		}
		return N.NewBindPacketConn(pc, currentMeta.UDPAddr()), nil
	}
	conn, err := p.proxy.DialContext(ctx, currentMeta)
	if err != nil {
		return nil, err
	}
	if p.statistic {
		conn = statistic.NewTCPTracker(conn, statistic.DefaultManager, currentMeta, nil, 0, 0, false)
	}
	return conn, err
}

func (p proxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	if !strings.HasPrefix(network, "udp") {
		return nil, fmt.Errorf("proxyDialer only support udp network, but got: %s", network)
	}
	if !rAddrPort.IsValid() {
		// A listen without a fixed remote (tailscale's magicsock underlay)
		// needs one socket that writes to and reads from many endpoints.
		// A single proxy UDP session carries per-packet destinations
		// (XUDP/packet-addr), which provides exactly those semantics.
		return p.listenPacketWildcard(ctx)
	}
	currentMeta := &C.Metadata{Type: C.INNER, DstIP: rAddrPort.Addr(), DstPort: rAddrPort.Port()}
	return p.listenPacket(ctx, currentMeta)
}

// wildcardAddrPlaceholder is the handshake destination for wildcard proxy UDP
// sessions. Every datagram of such a session carries its real destination in
// the session framing, so the handshake target itself is never contacted.
var wildcardAddrPlaceholder = netip.MustParseAddrPort("1.1.1.1:53")

func (p proxyDialer) listenPacketWildcard(ctx context.Context) (net.PacketConn, error) {
	dial := func(ctx context.Context) (C.PacketConn, error) {
		pc, err := p.listenPacket(ctx, &C.Metadata{Type: C.INNER, NetWork: C.UDP})
		if err == nil {
			return pc, nil
		}
		// Some proxy handshakes reject a destinationless request outright;
		// retry with a placeholder so the session can be established.
		return p.listenPacket(ctx, &C.Metadata{
			Type:    C.INNER,
			NetWork: C.UDP,
			DstIP:   wildcardAddrPlaceholder.Addr(),
			DstPort: wildcardAddrPlaceholder.Port(),
		})
	}
	pc, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	return &wildcardPacketConn{dial: dial, pc: pc}, nil
}

// wildcardPacketConn adapts a destinationless proxy UDP session to
// net.PacketConn. The underlying C.PacketConn already carries per-packet
// addresses. The wrapper pins LocalAddr to a UDP shape, because callers such
// as tailscale's magicsock treat it as a UDP socket address, and re-dials the
// session when it dies so listeners without their own rebind triggers, like
// magicsock on an otherwise idle network, recover after an underlay restart.
type wildcardPacketConn struct {
	mu     sync.Mutex
	pc     C.PacketConn
	dial   func(context.Context) (C.PacketConn, error)
	closed bool
}

func (w *wildcardPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero}
}

func (w *wildcardPacketConn) current() C.PacketConn {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pc
}

// replace dials a fresh session when prev is still the active one. It returns
// nil when the connection is closed or another goroutine re-dialed first.
func (w *wildcardPacketConn) replace(prev C.PacketConn) C.PacketConn {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.pc != prev {
		return nil
	}
	pc, err := w.dial(context.Background())
	if err != nil {
		return nil
	}
	_ = prev.Close()
	w.pc = pc
	return pc
}

func (w *wildcardPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	pc := w.current()
	if n, err = pc.WriteTo(p, addr); err == nil {
		return
	}
	if pc = w.replace(pc); pc == nil {
		return
	}
	return pc.WriteTo(p, addr)
}

// wildcardSessionStale bounds how long a wildcard session may stay silent
// before it is re-dialed. A killed proxy emits no FIN, so a stale read is the
// only liveness signal; re-dialing an idle-but-healthy session costs one
// handshake and also picks up proxy-group re-selections.
const wildcardSessionStale = time.Minute

func (w *wildcardPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		pc := w.current()
		_ = pc.SetReadDeadline(time.Now().Add(wildcardSessionStale))
		n, addr, err = pc.ReadFrom(p)
		if err == nil {
			_ = pc.SetReadDeadline(time.Time{})
			return
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			select {
			case <-time.After(time.Second):
			}
		}
		if w.isClosed() {
			return
		}
		// Replace the session on deadline (possibly silently dead) and on
		// error, then keep serving: tailscale tolerates endpoint churn, and
		// the caller has no rebind trigger of its own.
		_ = w.replace(pc)
	}
}

func (w *wildcardPacketConn) isClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

func (w *wildcardPacketConn) SetDeadline(t time.Time) error {
	return w.current().SetDeadline(t)
}

func (w *wildcardPacketConn) SetReadDeadline(t time.Time) error {
	return w.current().SetReadDeadline(t)
}

func (w *wildcardPacketConn) SetWriteDeadline(t time.Time) error {
	return w.current().SetWriteDeadline(t)
}

func (w *wildcardPacketConn) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.pc.Close()
}

func (p proxyDialer) listenPacket(ctx context.Context, currentMeta *C.Metadata) (C.PacketConn, error) {
	currentMeta.NetWork = C.UDP
	pc, err := p.proxy.ListenPacketContext(ctx, currentMeta)
	if err != nil {
		return nil, err
	}
	if p.statistic {
		pc = statistic.NewUDPTracker(pc, statistic.DefaultManager, currentMeta, nil, 0, 0, false)
	}
	return pc, nil
}
