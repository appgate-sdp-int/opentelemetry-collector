// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configspa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	const validHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "valid",
			cfg: Config{
				KeyName: "k1",
				Key:     validHexKey,
				Mode:    "udp-tcp",
			},
		},
		{
			name:    "empty key_name",
			cfg:     Config{Key: validHexKey, Mode: "tcp"},
			wantErr: `"key_name" must not be empty`,
		},
		{
			name:    "wrong key length",
			cfg:     Config{KeyName: "k1", Key: "deadbeef", Mode: "tcp"},
			wantErr: `"key" must be a 64-character`,
		},
		{
			name: "key not hex",
			cfg: Config{
				KeyName: "k1",
				Key:     "zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				Mode:    "tcp",
			},
			wantErr: `"key" is not valid hex`,
		},
		{
			name: "invalid mode",
			cfg: Config{
				KeyName: "k1",
				Key:     validHexKey,
				Mode:    "weird",
			},
			wantErr: `"mode" must be one of`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestSanitizedEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{"https with path", "https://host.example:443/telemetry", "host.example:443"},
		{"https no path", "https://host.example:443", "host.example:443"},
		{"http with path", "http://host.example:8080/v1/metrics", "host.example:8080"},
		{"host port only", "host.example:443", "host.example:443"},
		{"host port path no scheme", "host.example:443/telemetry", "host.example:443"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SanitizedEndpoint(tt.endpoint))
		})
	}
}

func TestHandleStopNil(t *testing.T) {
	assert.NotPanics(t, func() { (*Handle)(nil).Stop() })
	var h Handle
	assert.NotPanics(t, h.Stop)
}
