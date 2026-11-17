package libbox

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/service/powerreport"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Stop after real TUN construction: exercise SDK -> daemon -> box.New without
// opening an OS interface or requiring root. The captured options feed the stack.
func overrideTestServer(t *testing.T, capture func(string, option.TunInboundOptions) error) *CommandServer {
	t.Helper()
	previousBasePath := sBasePath
	sBasePath = t.TempDir()
	t.Cleanup(func() { sBasePath = previousBasePath })
	ctx := baseContext(nil)
	registry := service.FromContext[adapter.InboundRegistry](ctx).(*inbound.Registry)
	inbound.Register(registry, C.TypeTun, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunInboundOptions) (adapter.Inbound, error) {
		instance, err := tun.NewInbound(ctx, router, logger, tag, options)
		if err != nil {
			return nil, err
		}
		if err = capture(tag, options); err != nil {
			return nil, err
		}
		return instance, nil
	})
	started := daemon.NewStartedService(daemon.ServiceOptions{Context: ctx, LogMaxLines: 10})
	t.Cleanup(started.Close)
	return &CommandServer{StartedService: started, ctx: ctx, powerManager: powerreport.NewManager()}
}

func TestStartOrReloadServiceDisableIPv6(t *testing.T) {
	const profile = `{
		"log":{"disabled":true},
		"dns":{"servers":[{"type":"local","tag":"system"}]},
		"inbounds":[
			{"type":"tun","tag":"first","address":["172.19.0.1/30","fdfe:dcba:9876::1/126","172.20.0.1/30"],"dns_address":["172.19.0.2","fdfe:dcba:9876::2"],"auto_route":true,"auto_redirect":true,"route_address":["0.0.0.0/0","::/0"],"route_exclude_address":["192.168.0.0/16","fc00::/7"],"loopback_address":["10.7.0.1","fd00::1"],"include_package":["profile.include"],"exclude_package":["profile.exclude"],"mtu":1400,"stack":"mixed"},
			{"type":"tun","tag":"second","address":["172.21.0.1/30","fdfe:dcba:9877::1/126"],"auto_route":true,"auto_redirect":true,"stack":"system"}
		],
		"outbounds":[{"type":"socks","tag":"ipv6-node","server":"2001:db8::1","server_port":1080}],
		"route":{"rules":[{"ip_cidr":"2001:db8::/32","outbound":"ipv6-node"}]}
	}`
	original, err := parseConfig(baseContext(nil), profile)
	require.NoError(t, err)
	stop := errors.New("stop before opening TUN")
	var captured []option.TunInboundOptions
	server := overrideTestServer(t, func(tag string, options option.TunInboundOptions) error {
		captured = append(captured, options)
		if tag == "second" {
			return stop
		}
		return nil
	})
	for _, testCase := range []struct {
		name    string
		disable bool
	}{
		{"default dual stack", false},
		{"IPv4 only", true},
		{"dual stack restored from same profile", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			captured = nil
			err := server.StartOrReloadService(profile, &OverrideOptions{
				DisableIPv6:    testCase.disable,
				IncludePackage: newIterator([]string{"runtime.include"}),
				ExcludePackage: newIterator([]string{"runtime.exclude"}),
			})
			require.ErrorIs(t, err, stop)
			require.Len(t, captured, 2)
			first := *original.Inbounds[0].Options.(*option.TunInboundOptions)
			second := *original.Inbounds[1].Options.(*option.TunInboundOptions)
			// Existing overrides still affect only the first TUN; the family
			// invariant must cover every TUN consumed by box.New.
			first.AutoRedirect = false
			first.IncludePackage = []string{"profile.include", "runtime.include"}
			first.ExcludePackage = []string{"profile.exclude", "runtime.exclude"}
			if testCase.disable {
				first.Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30"), netip.MustParsePrefix("172.20.0.1/30")}
				first.DNSAddress = []netip.Addr{netip.MustParseAddr("172.19.0.2")}
				first.RouteAddress = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
				first.RouteExcludeAddress = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
				first.LoopbackAddress = []netip.Addr{netip.MustParseAddr("10.7.0.1")}
				second.Address = []netip.Prefix{netip.MustParsePrefix("172.21.0.1/30")}
			}
			require.Equal(t, []option.TunInboundOptions{first, second}, captured)
			snapshot, err := os.ReadFile(configSnapshotPath())
			require.NoError(t, err)
			require.Equal(t, profile, string(snapshot), "persist the original profile, not the runtime override")
		})
	}
}

func TestStartOrReloadServiceDisableIPv6DoesNotInventAddress(t *testing.T) {
	server := overrideTestServer(t, func(_ string, options option.TunInboundOptions) error {
		require.Empty(t, options.Address)
		// Both system and mixed use NewSystem. Keep its existing error rather
		// than supplying an IPv4 address when the profile contains only IPv6.
		_, err := singtun.NewSystem(singtun.StackOptions{
			TunOptions: singtun.Options{Inet4Address: options.Address},
		})
		return err
	})
	err := server.StartOrReloadService(
		`{"log":{"disabled":true},"inbounds":[{"type":"tun","address":["fdfe:dcba:9876::1/126"],"stack":"system"}]}`,
		&OverrideOptions{DisableIPv6: true},
	)
	require.ErrorContains(t, err, "missing interface address")
}

func TestStartOrReloadServiceDisableIPv6IncompatibleTUN(t *testing.T) {
	for _, testCase := range []struct {
		name, fields, wantError string
	}{
		{"IPv6 DNS only", `"address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"dns_address":["fdfe:dcba:9876::2"]`, "disable IPv6: no IPv4 TUN DNS address configured"},
		{"removed legacy address", `"address":["172.19.0.1/30"],"inet6_address":["fdfe:dcba:9876::1/126"]`, "legacy tun address fields"},
		{"removed legacy route", `"address":["172.19.0.1/30"],"inet6_route_address":["::/0"]`, "legacy tun address fields"},
		{"removed legacy exclusion", `"address":["172.19.0.1/30"],"inet6_route_exclude_address":["fc00::/7"]`, "legacy tun address fields"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := overrideTestServer(t, func(string, option.TunInboundOptions) error {
				t.Fatal("incompatible TUN configuration reached construction")
				return nil
			})
			profile := `{"log":{"disabled":true},"inbounds":[{"type":"tun","tag":"tun-in",` + testCase.fields + `}]}`
			err := server.StartOrReloadService(profile, &OverrideOptions{DisableIPv6: true})
			require.ErrorContains(t, err, testCase.wantError)
			snapshot, err := os.ReadFile(configSnapshotPath())
			require.NoError(t, err)
			require.Equal(t, profile, string(snapshot))
		})
	}
}
