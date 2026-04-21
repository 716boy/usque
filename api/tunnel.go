package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	// Write expects a slice of packet buffers.
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// MaintainTunnelConfig contains runtime settings for tunnel maintenance.
type MaintainTunnelConfig struct {
	TLSConfig         *tls.Config
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	Endpoint          net.Addr
	Device            TunnelDevice
	MTU               int
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
	UseHTTP2          bool
}

// pumpShutdownGrace is how long the reconnect logic waits for the previous
// pair of pump goroutines to exit before starting a new pair. Closing the
// IP-side connection synchronously unblocks the IP→device pump immediately.
// The device→IP pump can still be parked inside a TUN read; we cap the
// wait so we don't deadlock the supervisor, and rely on the next packet
// (which will then fail to write to the now-closed connection) to drain
// the stale goroutine on its own. The mutex around device reads (see
// pumpDeviceToIP) prevents the new and stale device readers from racing
// for the same packet during that brief overlap.
const pumpShutdownGrace = 5 * time.Second

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - cfg: MaintainTunnelConfig - Tunnel maintenance runtime configuration.
func MaintainTunnel(ctx context.Context, cfg MaintainTunnelConfig) {
	if cfg.UseHTTP2 {
		if _, ok := cfg.Endpoint.(*net.TCPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/2 mode requires a *net.TCPAddr endpoint, got %T", cfg.Endpoint)
		}
	} else {
		if _, ok := cfg.Endpoint.(*net.UDPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/3 mode requires a *net.UDPAddr endpoint, got %T", cfg.Endpoint)
		}
	}

	packetBufferPool := NewNetBuffer(cfg.MTU)

	// deviceReadMu serializes ReadPacket calls on cfg.Device across the
	// (possibly transient) overlap between an old, draining pump goroutine
	// and the freshly-spawned one for the next session. Without this, a
	// stale device reader could steal a packet from the new session and
	// then fail to write it to the closed IP connection, dropping that
	// packet entirely.
	var deviceReadMu sync.Mutex

	for {
		if ctx.Err() != nil {
			log.Printf("MaintainTunnel: context cancelled, exiting: %v", ctx.Err())
			return
		}

		if !cfg.AlwaysReconnect {
			log.Println("Tunnel idle. Waiting for outbound activity before reconnecting...")
			buf := packetBufferPool.Get()
			deviceReadMu.Lock()
			n, err := cfg.Device.ReadPacket(buf)
			deviceReadMu.Unlock()
			if err != nil {
				packetBufferPool.Put(buf)
				log.Printf("Failed to read from TUN device while waiting for activity: %v", err)
				time.Sleep(cfg.ReconnectDelay)
				continue
			}
			packetBufferPool.Put(buf)
			log.Printf("Detected outbound activity (%d bytes). Reconnecting...", n)
		}

		log.Printf("Establishing MASQUE connection to %s", cfg.Endpoint)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			ctx,
			cfg.TLSConfig,
			internal.DefaultQuicConfig(cfg.KeepalivePeriod, cfg.InitialPacketSize),
			internal.ConnectURI,
			cfg.Endpoint,
			cfg.UseHTTP2,
		)
		if err != nil {
			// Bug 2 fix: ConnectTunnel may return partially-allocated
			// resources (e.g. the UDP socket) alongside the error. The
			// previous version logged the error and continued, leaking
			// the file descriptors on every failed reconnect attempt
			// until the process eventually hit ulimit.
			closeIfNotNil(ipConn, udpConn, tr)
			log.Printf("Failed to connect tunnel: %v", err)
			sleepOrCancel(ctx, cfg.ReconnectDelay)
			continue
		}
		if rsp != nil && rsp.StatusCode != 200 {
			log.Printf("Tunnel connection failed: %s", rsp.Status)
			closeIfNotNil(ipConn, udpConn, tr)
			sleepOrCancel(ctx, cfg.ReconnectDelay)
			continue
		}

		log.Println("Connected to MASQUE server")

		// Bug 1 fix: previously the supervisor used a buffered errChan
		// and only read one error before reconnecting, leaving the
		// peer goroutine alive. After several reconnects, multiple
		// stale goroutines were racing for the same TUN device and IP
		// connection, dropping packets and corrupting state. We now
		// gate every reconnect on a WaitGroup so the previous pair has
		// exited (or the grace window expired) before the next pair
		// is spawned.
		pumpCtx, pumpCancel := context.WithCancel(ctx)
		errChan := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)

		go pumpDeviceToIP(pumpCtx, &wg, errChan, cfg.Device, ipConn, packetBufferPool, &deviceReadMu)
		go pumpIPToDevice(pumpCtx, &wg, errChan, cfg.Device, ipConn, packetBufferPool, cfg.UseHTTP2)

		err = <-errChan
		log.Printf("Tunnel connection lost: %v. Reconnecting...", err)

		// Cancel the pump context first so any select-aware code paths
		// stop early, then close the IP connection to unblock the
		// IP→device pump's blocking read/write. The device→IP pump
		// will exit either when its current TUN read returns (and the
		// subsequent IP write fails) or, if the device is idle, when
		// the grace window expires.
		pumpCancel()
		closeIfNotNil(ipConn, udpConn, tr)
		waitForPumps(&wg, pumpShutdownGrace)

		sleepOrCancel(ctx, cfg.ReconnectDelay)
	}
}

// pumpDeviceToIP forwards packets from the TUN device to the MASQUE IP
// connection and writes any synchronous ICMP reply back to the device.
// It signals exit via errChan and the WaitGroup; it always sends exactly
// one value to errChan so the supervisor can select on it.
func pumpDeviceToIP(
	ctx context.Context,
	wg *sync.WaitGroup,
	errChan chan<- error,
	device TunnelDevice,
	ipConn *connectip.Conn,
	pool *NetBuffer,
	deviceReadMu *sync.Mutex,
) {
	defer wg.Done()
	sent := false
	send := func(err error) {
		if sent {
			return
		}
		sent = true
		select {
		case errChan <- err:
		default:
			// Buffer is full because the peer goroutine already
			// reported an error. Nothing to do.
		}
	}

	for {
		if ctx.Err() != nil {
			send(fmt.Errorf("device→ip pump: context cancelled: %w", ctx.Err()))
			return
		}

		buf := pool.Get()

		deviceReadMu.Lock()
		n, err := device.ReadPacket(buf)
		deviceReadMu.Unlock()
		if err != nil {
			pool.Put(buf)
			send(fmt.Errorf("failed to read from TUN device: %w", err))
			return
		}

		// If we were cancelled while parked in ReadPacket, drop the
		// packet rather than write to a connection the supervisor
		// already closed.
		if ctx.Err() != nil {
			pool.Put(buf)
			send(fmt.Errorf("device→ip pump: context cancelled after read: %w", ctx.Err()))
			return
		}

		icmp, err := ipConn.WritePacket(buf[:n])
		if err != nil {
			pool.Put(buf)
			if errors.As(err, new(*connectip.CloseError)) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				send(fmt.Errorf("connection closed while writing to IP connection: %w", err))
				return
			}
			log.Printf("Error writing to IP connection: %v, continuing...", err)
			continue
		}
		pool.Put(buf)

		if len(icmp) > 0 {
			if err := device.WritePacket(icmp); err != nil {
				if errors.As(err, new(*connectip.CloseError)) || errors.Is(err, net.ErrClosed) {
					send(fmt.Errorf("connection closed while writing ICMP to TUN device: %w", err))
					return
				}
				log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
			}
		}
	}
}

// pumpIPToDevice forwards packets from the MASQUE IP connection to the TUN
// device. It uses a single owned buffer for the lifetime of the goroutine
// (the underlying ReadPacket fills the same scratch on every call). It
// signals exit via errChan and the WaitGroup.
func pumpIPToDevice(
	ctx context.Context,
	wg *sync.WaitGroup,
	errChan chan<- error,
	device TunnelDevice,
	ipConn *connectip.Conn,
	pool *NetBuffer,
	useHTTP2 bool,
) {
	defer wg.Done()
	buf := pool.Get()
	defer pool.Put(buf)

	sent := false
	send := func(err error) {
		if sent {
			return
		}
		sent = true
		select {
		case errChan <- err:
		default:
		}
	}

	for {
		if ctx.Err() != nil {
			send(fmt.Errorf("ip→device pump: context cancelled: %w", ctx.Err()))
			return
		}

		n, err := ipConn.ReadPacket(buf, true)
		if err != nil {
			if useHTTP2 {
				send(fmt.Errorf("connection closed while reading from IP connection: %w", err))
				return
			}
			if errors.As(err, new(*connectip.CloseError)) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				send(fmt.Errorf("connection closed while reading from IP connection: %w", err))
				return
			}
			log.Printf("Error reading from IP connection: %v, continuing...", err)
			continue
		}
		if err := device.WritePacket(buf[:n]); err != nil {
			send(fmt.Errorf("failed to write to TUN device: %w", err))
			return
		}
	}
}

// waitForPumps blocks until both pump goroutines exit, or until grace
// elapses. A timeout is logged but not fatal: the stale goroutine will
// notice the closed IP connection on its next operation and exit on its
// own. Returning here lets the supervisor proceed with the next reconnect
// even if a TUN read is parked for a long time.
func waitForPumps(wg *sync.WaitGroup, grace time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(grace):
		log.Printf("Tunnel pump did not exit within %s; continuing reconnect (stale goroutine will drain on next packet)", grace)
	}
}

// sleepOrCancel waits for d or until ctx is done, whichever comes first.
// Replaces the bare time.Sleep that previously made the reconnect loop
// unresponsive to context cancellation.
func sleepOrCancel(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// closeIfNotNil closes a heterogeneous set of optional resources in a
// fixed order (IP connection first, so any blocked reads on the underlying
// transport unblock before we drop their owner) and ignores Close errors
// because we are already on an error path.
func closeIfNotNil(ipConn *connectip.Conn, udpConn *net.UDPConn, tr io.Closer) {
	if ipConn != nil {
		_ = ipConn.Close()
	}
	if tr != nil {
		_ = tr.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}
