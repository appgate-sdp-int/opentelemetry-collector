// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configgrpc // import "go.opentelemetry.io/collector/config/configgrpc"

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"

	"google.golang.org/grpc/credentials"

	"go.opentelemetry.io/collector/config/configspa"
)

// tlsConfigLoader produces the base *tls.Config for each handshake. Decoupled
// from configtls so spa_creds can be tested with a stub.
type tlsConfigLoader func(ctx context.Context) (*tls.Config, error)

// newSPACredentials returns gRPC TransportCredentials that perform a TLS
// handshake augmented with a libspa-generated ClientHello extension. The
// resulting conn negotiates HTTP/2 over ALPN like stock TLS credentials would.
//
// loadTLS is invoked per dial to obtain the base *tls.Config; the returned
// config is cloned, the SPA extension is appended to HelloExtensions, and the
// clone is used for the actual handshake. endpoint is host:port; cfg carries
// the libspa PSK and mode.
//
// The credential expects the underlying net.Conn passed to ClientHandshake to
// be a *spaConn produced by newSPADialer: the libspa context — and its derived
// TLS ClientHello extension — is created there, before the TCP dial, so that
// hybrid (udp-tcp) mode can open the SPA cloak before gRPC establishes the
// TCP connection. Doing SPA-UDP inside ClientHandshake would be too late
// because gRPC only calls it after TCP has succeeded.
func newSPACredentials(endpoint string, cfg *configspa.Config, loadTLS tlsConfigLoader) credentials.TransportCredentials {
	return &spaCreds{endpoint: endpoint, cfg: cfg, loadTLS: loadTLS}
}

type spaCreds struct {
	endpoint string
	cfg      *configspa.Config
	loadTLS  tlsConfigLoader
}

// spaConn wraps the raw TCP net.Conn produced by newSPADialer and carries the
// configspa handle whose TLS ClientHello extension must be layered into the
// TLS handshake by (*spaCreds).ClientHandshake. Ownership of the handle
// transfers to ClientHandshake, which is responsible for Stop()ing it.
type spaConn struct {
	net.Conn
	handle *configspa.Handle
}

// newSPADialer returns a grpc.WithContextDialer callback that sends the SPA-UDP
// probe (via configspa.Start) before dialing TCP. The returned net.Conn is a
// *spaConn wrapping the TCP conn together with the libspa handle, so that the
// SPA-derived TLS ClientHello extension is available to ClientHandshake.
//
// endpoint is host:port and is used by libspa for IP resolution and per-connection
// logging. It is not used as the dial target — that is the addr grpc passes in,
// which may differ (e.g. when a resolver expands a hostname).
func newSPADialer(endpoint string, cfg *configspa.Config) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		handle, err := configspa.Start(endpoint, cfg)
		if err != nil {
			return nil, err
		}
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			handle.Stop()
			return nil, fmt.Errorf("spa: TCP dial: %w", err)
		}
		return &spaConn{Conn: conn, handle: handle}, nil
	}
}

func (c *spaCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
		ServerName:       "",
	}
}

func (c *spaCreds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	sc, ok := rawConn.(*spaConn)
	if !ok {
		// The SPA credential is only wired together with newSPADialer via
		// grpc.WithContextDialer; getting anything else here means the dial
		// options were misconfigured.
		return nil, nil, errors.New("spa: internal error: expected *spaConn from SPA dialer")
	}
	// Ownership of the libspa handle transfers here.
	defer sc.handle.Stop()

	baseCfg, err := c.loadTLS(ctx)
	if err != nil {
		sc.Conn.Close()
		return nil, nil, fmt.Errorf("spa: loading TLS config: %w", err)
	}
	if baseCfg == nil {
		// configtls returns nil when Insecure==true && no CA — SPA cannot inject
		// its extension without a TLS handshake. Surface that as a permanent
		// configuration error.
		sc.Conn.Close()
		return nil, nil, errors.New("spa: cloaking requires TLS; configure tls block (insecure: false)")
	}
	dialCfg := baseCfg.Clone()

	serverName, _, splitErr := net.SplitHostPort(authority)
	if splitErr != nil {
		serverName = authority
	}
	if dialCfg.ServerName == "" {
		dialCfg.ServerName = serverName
	}
	dialCfg.NextProtos = appendH2(dialCfg.NextProtos)

	dialCfg.HelloExtensions = append(dialCfg.HelloExtensions, sc.handle.TLSHelloExtension())

	conn := tls.Client(sc.Conn, dialCfg)

	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()

		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, fmt.Errorf("spa: TLS handshake: %w", err)
	}

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		conn.Close()
		return nil, nil, fmt.Errorf("spa: server did not negotiate h2 (got %q); SPA gRPC client only supports HTTP/2", state.NegotiatedProtocol)
	}

	return conn, credentials.TLSInfo{
		State: state,
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}, nil
}

func (c *spaCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("spa: ServerHandshake not supported (client-side credentials)")
}

func (c *spaCreds) Clone() credentials.TransportCredentials {
	dup := *c
	return &dup
}

func (c *spaCreds) OverrideServerName(string) error {
	// gRPC keeps this for legacy WithServerName; we honor server name via the
	// authority parameter to ClientHandshake instead.
	return nil
}

func appendH2(protos []string) []string {
	if slices.Contains(protos, "h2") {
		return protos
	}
	return append(protos, "h2")
}
