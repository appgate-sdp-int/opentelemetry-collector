// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configspa // import "go.opentelemetry.io/collector/config/configspa"

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/appgate-sdp-int/gopackages/v2/libspa"
)

// Handle owns a libspa client context together with its derived TLS hello
// extension. It is intentionally opaque: callers only need the extension and a
// cleanup hook.
type Handle struct {
	hello tls.HelloExtension
	stop  func()
}

// Stop releases the underlying libspa client context. Safe to call multiple
// times and on a nil receiver.
func (h *Handle) Stop() {
	if h == nil || h.stop == nil {
		return
	}
	h.stop()
	h.stop = nil
}

// TLSHelloExtension returns the SPA-derived TLS ClientHello extension. Callers
// append this to (*tls.Config).HelloExtensions before handshaking.
func (h *Handle) TLSHelloExtension() tls.HelloExtension {
	return h.hello
}

// Start creates a libspa client context for the given endpoint and (in hybrid
// modes) emits the SPA-UDP probe. endpoint is host:port; cfg carries the PSK
// and mode. Callers must invoke Handle.Stop when the associated TLS handshake
// completes — or fails — to release the context.
func Start(endpoint string, cfg *Config) (*Handle, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("spa: extracting host:port from %q: %w", endpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("spa: invalid port %q: %w", portStr, err)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("spa: looking up %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("spa: %q resolved to no IPs", host)
	}

	cc := libspa.ConnectCtx{
		SPAParams: libspa.ConnectParameters{
			KeyName:       cfg.KeyName,
			Key:           cfg.Key,
			Mode:          cfg.Mode,
			AccessService: libspa.AccessNginxPeer,
			Port:          port,
			IP:            ips[0].String(),
		},
	}

	libspaCtx, err := cc.CreateClientLibspaCtx(endpoint)
	if err != nil {
		return nil, fmt.Errorf("spa: creating libspa client context: %w", err)
	}

	if err := cc.SPAoverUDP(libspaCtx, false); err != nil {
		libspa.DestroyClientLibspaCtx(libspaCtx)
		return nil, fmt.Errorf("spa: sending SPA-UDP: %w", err)
	}

	hello := libspa.CreateTLSHelloExtension(libspaCtx)
	if len(hello.Data) == 0 {
		libspa.DestroyClientLibspaCtx(libspaCtx)
		return nil, errors.New("spa: empty TLS hello extension from libspa")
	}

	return &Handle{
		hello: hello,
		stop:  func() { libspa.DestroyClientLibspaCtx(libspaCtx) },
	}, nil
}
