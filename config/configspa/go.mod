module go.opentelemetry.io/collector/config/configspa

go 1.25.0

require (
	github.com/appgate-sdp-int/gopackages/v2 v2.2.9
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/jellydator/ttlcache/v3 v3.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Stage-1 SPA-OTLP exporter: libspa Go bindings live in a sibling repo that
// the OCB builder container bind-mounts (see otelcol/build.toml [[mounts]]).
//replace github.com/appgate-sdp-int/gopackages/v2 => /build/gopackages
