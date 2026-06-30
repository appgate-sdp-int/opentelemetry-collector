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
func newSPACredentials(endpoint string, cfg *configspa.Config, loadTLS tlsConfigLoader) credentials.TransportCredentials {
	return &spaCreds{endpoint: endpoint, cfg: cfg, loadTLS: loadTLS}
}

type spaCreds struct {
	endpoint string
	cfg      *configspa.Config
	loadTLS  tlsConfigLoader
}

func (c *spaCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
		ServerName:       "",
	}
}

func (c *spaCreds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	baseCfg, err := c.loadTLS(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("spa: loading TLS config: %w", err)
	}
	if baseCfg == nil {
		// configtls returns nil when Insecure==true && no CA — SPA cannot inject
		// its extension without a TLS handshake. Surface that as a permanent
		// configuration error.
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

	handle, err := configspa.Start(c.endpoint, c.cfg)
	if err != nil {
		return nil, nil, err
	}
	defer handle.Stop()
	dialCfg.HelloExtensions = append(dialCfg.HelloExtensions, handle.TLSHelloExtension())

	conn := tls.Client(rawConn, dialCfg)

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
