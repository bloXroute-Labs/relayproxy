package relayproxy

import (
	"context"
	"strings"
	"sync"
	"time"

	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy/common"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	windowSize = 1024 * 1024 * 10 // 3 MB
	bufferSize = 1024 * 1024 * 8  // 8 MB

)

type Dialer struct {
	DialerClients     *DialerClients
	DialerConnections *DialerConnections
	DialURL           *DialURL
}

type DialerClients struct {
	mu                    sync.RWMutex
	clients               []*common.Client
	streamingClients      []*common.Client
	streamingBlockClients []*common.Client
	registrationClients   []*common.Client
}

func (d *DialerClients) CopyClients() []*common.Client {
	d.mu.RLock()
	defer d.mu.RUnlock()

	copiedClients := make([]*common.Client, len(d.clients))
	copy(copiedClients, d.clients)

	return copiedClients
}

type DialerConnections struct {
	Conns               []*grpc.ClientConn
	StreamingConns      []*grpc.ClientConn
	RegConns            []*grpc.ClientConn
	StreamingBlockConns []*grpc.ClientConn
}

type DialURL struct {
	RelayURL          string
	StreamingURL      string
	RegistrationURL   string
	StreamingBlockURL string
}

func NewDialer(dialerOpts ...DialerOption) *Dialer {
	dialer := &Dialer{
		DialerClients: &DialerClients{
			clients:               make([]*common.Client, 0),
			streamingClients:      make([]*common.Client, 0),
			streamingBlockClients: make([]*common.Client, 0),
			registrationClients:   make([]*common.Client, 0),
		},
		DialerConnections: &DialerConnections{
			Conns:               make([]*grpc.ClientConn, 0),
			StreamingConns:      make([]*grpc.ClientConn, 0),
			RegConns:            make([]*grpc.ClientConn, 0),
			StreamingBlockConns: make([]*grpc.ClientConn, 0),
		},
		DialURL: &DialURL{},
	}

	for _, option := range dialerOpts {
		option(dialer)
	}

	return dialer
}

func (d *Dialer) SetDialer(l *zap.Logger) {
	// Close all existing connections, if available
	d.CloseConnections()

	// A helper function that dials the given URLs and returns slices of clients and connections.
	dialAndSetConnections := func(url string) ([]*common.Client, []*grpc.ClientConn) {
		var clients []*common.Client
		var conns []*grpc.ClientConn

		keepaliveOpts := grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Minute,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		})

		relays := strings.Split(url, ",")
		for _, relayURL := range relays {
			l.Info("attempting to dial relay", zap.String("relayURL", relayURL))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			conn, err := grpc.DialContext( //nolint:staticcheck
				ctx,
				relayURL,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				keepaliveOpts,
				grpc.WithInitialConnWindowSize(windowSize),
				grpc.WithWriteBufferSize(bufferSize),
			)
			cancel()

			if err != nil {
				l.Error("failed to dial relay", zap.String("relayURL", relayURL), zap.Error(err))
				continue
			}

			l.Info("successfully dialed relay", zap.String("relayURL", relayURL))
			conns = append(conns, conn)
			clients = append(clients, &common.Client{
				URL:         relayURL,
				RelayClient: relaygrpc.NewRelayClient(conn),
			})
		}

		l.Info("finished dialing connections",
			zap.String("configURL", url),
			zap.Int("totalConnections", len(conns)))
		return clients, conns
	}

	// Dial connection groups and update the dialer fields.
	d.DialerClients.clients, d.DialerConnections.Conns = dialAndSetConnections(d.DialURL.RelayURL)
	d.DialerClients.streamingClients, d.DialerConnections.StreamingConns = dialAndSetConnections(d.DialURL.StreamingURL)
	d.DialerClients.registrationClients, d.DialerConnections.RegConns = dialAndSetConnections(d.DialURL.RegistrationURL)
	d.DialerClients.streamingBlockClients, d.DialerConnections.StreamingBlockConns = dialAndSetConnections(d.DialURL.StreamingBlockURL)

	// Check that all required connection groups have at least one connection.
	if len(d.DialerConnections.Conns) == 0 ||
		len(d.DialerConnections.StreamingConns) == 0 ||
		len(d.DialerConnections.RegConns) == 0 ||
		len(d.DialerConnections.StreamingBlockConns) == 0 {
		l.Info("failed to establish grpc connections for all URLs")
	}
}

func (d *Dialer) CloseConnections() {
	for _, conn := range d.DialerConnections.Conns {
		if conn != nil {
			conn.Close()
		}
	}
	for _, conn := range d.DialerConnections.StreamingConns {
		if conn != nil {
			conn.Close()
		}
	}
	for _, conn := range d.DialerConnections.RegConns {
		if conn != nil {
			conn.Close()
		}
	}
	for _, conn := range d.DialerConnections.StreamingBlockConns {
		if conn != nil {
			conn.Close()
		}
	}

	d.DialerConnections.Conns = nil
	d.DialerConnections.StreamingConns = nil
	d.DialerConnections.RegConns = nil
	d.DialerConnections.StreamingBlockConns = nil
}

func (d *Dialer) MonitorDialerHealth(l *zap.Logger, svc *Service, failOverThreshold int, dialerOpts ...DialerOption) {
	var failoverCounter int

	for {
		if err := svc.HealthCheck(); err != nil {
			l.Error("primary relay health check failed,increasing counter", zap.Error(err))
			failoverCounter++
		} else {
			failoverCounter = 0
		}

		if failoverCounter >= failOverThreshold {
			l.Warn("primary connections are down after multiple failed attempts, switching to fail over")
			// close previous connections
			d.CloseConnections()
			failOverDialer := NewDialer(dialerOpts...)     // create new fail over dialer
			svc.UpdateDialer(failOverDialer.DialerClients) // update the service dialer clients

			failoverCounter = 0
		}

		time.Sleep(10 * time.Second)
	}
}
