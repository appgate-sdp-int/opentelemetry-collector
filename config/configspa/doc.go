// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package configspa implements Single Packet Authorization (SPA) cloaking
// helpers shared by confighttp and configgrpc. It owns the libspa wrapper and
// the user-facing SPA configuration type so SPA support can be added to any
// confighttp/configgrpc-based component without duplicating libspa glue.
package configspa // import "go.opentelemetry.io/collector/config/configspa"
