// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configspa // import "go.opentelemetry.io/collector/config/configspa"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Config configures libspa client-side cloaking on a TLS transport.
// The PSK (KeyName + Key) must match what the SPA-cloaked server listener
// is provisioned with.
type Config struct {
	KeyName string `mapstructure:"key_name"`
	Key     string `mapstructure:"key"`
	Mode    string `mapstructure:"mode"`
}

var validModes = map[string]struct{}{
	"tcp":     {},
	"udp":     {},
	"udp-tcp": {},
}

// aes256HexKeyLen is the expected hex length of a 32-byte AES-256 key.
const aes256HexKeyLen = 64

// Validate checks PSK length/encoding, the SPA mode
func (c *Config) Validate() error {
	if c.KeyName == "" {
		return errors.New(`spa: "key_name" must not be empty`)
	}
	if len(c.Key) != aes256HexKeyLen {
		return fmt.Errorf(`spa: "key" must be a %d-character AES-256 hex string`, aes256HexKeyLen)
	}
	if _, err := hex.DecodeString(c.Key); err != nil {
		return fmt.Errorf(`spa: "key" is not valid hex: %w`, err)
	}
	if _, ok := validModes[c.Mode]; !ok {
		return fmt.Errorf(`spa: "mode" must be one of tcp, udp, udp-tcp (got %q)`, c.Mode)
	}
	return nil
}

// SanitizedEndpoint reduces an endpoint string to host:port. confighttp and
// configgrpc Endpoint fields may carry a scheme and (for HTTP) a path; libspa
// only wants host:port for IP resolution and per-connection logging.
func SanitizedEndpoint(endpoint string) string {
	if strings.Contains(endpoint, "://") {
		if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
			if _, _, err := net.SplitHostPort(u.Host); err == nil {
				return u.Host
			}
			switch strings.ToLower(u.Scheme) {
			case "https":
				return net.JoinHostPort(u.Hostname(), "443")
			case "http":
				return net.JoinHostPort(u.Hostname(), "80")
			default:
				return u.Host
			}
		}
	}
	if i := strings.IndexByte(endpoint, '/'); i >= 0 {
		return endpoint[:i]
	}
	return endpoint
}
