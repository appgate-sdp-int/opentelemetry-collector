// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configspa // import "go.opentelemetry.io/collector/config/configspa"

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

// NewDialTLSContext returns a callback suitable for (*http.Transport).DialTLSContext.
// On each dial it starts a libspa context, appends the SPA-derived ClientHello
// extension to a clone of baseTLS, performs the TLS dial, and releases the
// libspa context before returning. endpoint is host:port and is used for IP
// resolution and the per-connection log identifier — not as the dial target;
// the caller's transport supplies addr, which may differ when a proxy is used.
//
// baseTLS must be non-nil: SPA cloaking requires a real TLS handshake to carry
// the ClientHello extension that opens the cloaked listener.
func NewDialTLSContext(endpoint string, cfg *Config, baseTLS *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if baseTLS == nil {
			return nil, errors.New("spa: cloaking requires TLS; configure tls block (insecure: false)")
		}
		dialCfg := baseTLS.Clone()
		if dialCfg.ServerName == "" {
			if host, _, err := net.SplitHostPort(addr); err == nil {
				dialCfg.ServerName = host
			}
		}

		handle, err := Start(endpoint, cfg)
		if err != nil {
			return nil, err
		}
		defer handle.Stop()
		dialCfg.HelloExtensions = append(dialCfg.HelloExtensions, handle.TLSHelloExtension())

		d := tls.Dialer{Config: dialCfg}
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("spa: TLS dial: %w", err)
		}
		return conn, nil
	}
}
