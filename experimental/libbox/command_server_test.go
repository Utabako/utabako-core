package libbox

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/locale"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/service/powerreport"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// Stop after real TUN construction: exercise SDK -> daemon -> box.New without
// opening an OS interface or requiring root. The captured options feed the stack.
func overrideTestServer(t *testing.T, capture func(string, option.TunInboundOptions) error) *CommandServer {
	t.Helper()
	server := newTestCommandServer(t)
	registry := service.FromContext[adapter.InboundRegistry](server.ctx).(*inbound.Registry)
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
	return server
}

func newTestCommandServer(t *testing.T) *CommandServer {
	t.Helper()
	previousBasePath := sBasePath
	sBasePath = t.TempDir()
	t.Cleanup(func() { sBasePath = previousBasePath })
	ctx := filemanager.WithDefault(baseContext(nil), sBasePath, sBasePath, os.Getuid(), os.Getgid())
	started := daemon.NewStartedService(daemon.ServiceOptions{Context: ctx, LogMaxLines: 10})
	t.Cleanup(func() {
		_ = started.CloseService()
		started.Close()
	})
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

func TestStartOrReloadServicePreCanceled(t *testing.T) {
	server := newTestCommandServer(t)
	options := new(OverrideOptions)
	options.Cancel()

	require.NoError(t, server.StartOrReloadService("invalid config", options))
	require.NoFileExists(t, configSnapshotPath())
	require.Nil(t, server.StartedService.Instance())
	require.Empty(t, server.GetStartupStage())
}

const startupProbeType = "startup-probe"
const startupProbeProfile = `{"log":{"disabled":true},"inbounds":[{"type":"startup-probe"}]}`

type startupProbeInbound struct {
	inbound.Adapter
	onStart func()
}

func (i *startupProbeInbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage == adapter.StartStateInitialize && i.onStart != nil {
		i.onStart()
	}
	return nil
}

type startupStatusStream struct {
	grpc.ServerStreamingServer[daemon.ServiceStatus]
	ctx     context.Context
	updates chan daemon.ServiceStatus_Type
}

func (s *startupStatusStream) Context() context.Context { return s.ctx }

func (s *startupStatusStream) Send(status *daemon.ServiceStatus) error {
	select {
	case s.updates <- status.Status:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func awaitStartupProbe[T any](t *testing.T, ctx context.Context, updates <-chan T) T {
	t.Helper()
	select {
	case update := <-updates:
		return update
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		var zero T
		return zero
	}
}

func TestStartOrReloadServiceCancelsConstruction(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		close bool
	}{
		{"options cancellation", false},
		{"close service", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testCtx, timeout := context.WithTimeout(t.Context(), 10*time.Second)
			defer timeout()
			server := newTestCommandServer(t)
			updates := make(chan daemon.ServiceStatus_Type, 4)
			go func() {
				_ = server.StartedService.SubscribeServiceStatus(nil, &startupStatusStream{ctx: testCtx, updates: updates})
			}()
			require.Equal(t, daemon.ServiceStatus_IDLE, awaitStartupProbe(t, testCtx, updates))

			loading := make(chan struct{})
			beginWait := make(chan struct{})
			waiting := make(chan struct{})
			constructorErr := make(chan error, 1)
			registry := service.FromContext[adapter.InboundRegistry](server.ctx).(*inbound.Registry)
			var startedInbound bool
			inbound.Register(registry, startupProbeType, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Inbound, error) {
				progress := service.PtrFromContext[adapter.RuleSetStartup](ctx)
				if progress == nil {
					return nil, errors.New("startup progress did not reach box construction")
				}
				defer progress.BeginLoading()()
				close(loading)
				select {
				case <-beginWait:
				case <-testCtx.Done():
					return nil, testCtx.Err()
				}
				defer progress.BeginZeroTierWait()()
				close(waiting)
				select {
				case <-ctx.Done():
					constructorErr <- ctx.Err()
					return &startupProbeInbound{
						Adapter: inbound.NewAdapter(startupProbeType, tag),
						onStart: func() { startedInbound = true },
					}, nil
				case <-testCtx.Done():
					return nil, testCtx.Err()
				}
			})
			options := new(OverrideOptions)
			started := make(chan error, 1)
			go func() { started <- server.StartOrReloadService(startupProbeProfile, options) }()

			awaitStartupProbe(t, testCtx, loading)
			require.Equal(t, daemon.ServiceStatus_STARTING, awaitStartupProbe(t, testCtx, updates))
			require.Equal(t, "loading-rule-sets", server.GetStartupStage())
			close(beginWait)
			awaitStartupProbe(t, testCtx, waiting)
			require.Equal(t, "waiting-zerotier-authorization", server.GetStartupStage())
			require.Nil(t, server.StartedService.Instance(), "constructor has not returned")
			if testCase.close {
				closed := make(chan error, 1)
				go func() { closed <- server.CloseService() }()
				require.NoError(t, awaitStartupProbe(t, testCtx, closed))
			} else {
				options.Cancel()
			}
			require.ErrorIs(t, awaitStartupProbe(t, testCtx, constructorErr), context.Canceled)
			require.NoError(t, awaitStartupProbe(t, testCtx, started))
			require.Equal(t, daemon.ServiceStatus_STOPPING, awaitStartupProbe(t, testCtx, updates))
			require.Equal(t, daemon.ServiceStatus_IDLE, awaitStartupProbe(t, testCtx, updates))
			require.False(t, startedInbound)
			require.Nil(t, server.StartedService.Instance())
			require.Empty(t, server.GetStartupStage())
		})
	}
}

func TestStartupCancellationDoesNotStopStartedInstance(t *testing.T) {
	server := newTestCommandServer(t)
	var boxCtx context.Context
	registry := service.FromContext[adapter.InboundRegistry](server.ctx).(*inbound.Registry)
	inbound.Register(registry, startupProbeType, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Inbound, error) {
		boxCtx = ctx
		return &startupProbeInbound{Adapter: inbound.NewAdapter(startupProbeType, tag)}, nil
	})
	options := new(OverrideOptions)
	requestCtx, ok := locale.ContextWithLocale(t.Context(), "zh-Hans")
	require.True(t, ok)
	requestCtx, cancel := context.WithCancel(requestCtx)
	cancel()

	// An RPC request contributes its locale, not its cancellation.
	require.NoError(t, server.StartedService.StartOrReloadService(requestCtx, startupProbeProfile, &daemon.OverrideOptions{
		Cancellation: &options.cancellation,
	}))
	instance := server.StartedService.Instance()
	require.NotNil(t, instance)
	require.Empty(t, server.GetStartupStage())
	require.Equal(t, "zh-Hans", locale.FromContext(boxCtx).Locale)

	options.Cancel()
	require.NoError(t, boxCtx.Err())
	require.NoError(t, server.StartOrReloadService("invalid config", options))
	require.Same(t, instance, server.StartedService.Instance())

	require.NoError(t, server.CloseService())
	require.ErrorIs(t, boxCtx.Err(), context.Canceled)
}
