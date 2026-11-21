//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	zt "github.com/Utabako/zt"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	singJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

func TestBoxColdZeroTierRuleSetStartup(t *testing.T) {
	const rules = `{"version":1,"rules":[{"domain":["overlay.example"]}]}`
	const ruleURL = "http://192.0.2.2:8080/rules.json"
	for _, test := range []struct {
		name                string
		status              zt.VirtualNetworkStatus
		response            int
		cancel, seed, cache bool
	}{
		{name: "authorize", status: zt.NetworkStatusAccessDenied, response: http.StatusOK},
		{name: "cancel", status: zt.NetworkStatusAuthenticationRequired, cancel: true},
		{name: "already joined HTTP error", status: zt.NetworkStatusOK, response: http.StatusForbidden},
		{name: "initial path", status: zt.NetworkStatusAccessDenied, seed: true},
		{name: "persisted cache", status: zt.NetworkStatusAccessDenied, cache: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			progress := new(adapter.RuleSetStartup)
			ctx = service.ContextWithPtr(ctx, progress)
			tunStarted := make(chan struct{})
			inboundRegistry := inbound.NewRegistry()
			inbound.Register(inboundRegistry, C.TypeTun, func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Inbound, error) {
				return &ruleSetStartupInbound{Adapter: inbound.NewAdapter(C.TypeTun, tag), started: tunStarted}, nil
			})
			outboundRegistry := outbound.NewRegistry()
			direct.RegisterOutbound(outboundRegistry)
			dnsRegistry := dns.NewTransportRegistry()
			local.RegisterTransport(dnsRegistry)
			ready := zt.VirtualNetworkConfig{
				Status: zt.NetworkStatusOK, MAC: 0x020000000001,
				AssignedAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")},
			}
			var ep *Endpoint
			var node *tcpPeerNode
			var tcpSent <-chan struct{}
			var requests atomic.Int32
			requestSeen := make(chan string, 1)
			allowResponse := make(chan struct{})
			endpointRegistry := endpoint.NewRegistry()
			endpoint.Register(endpointRegistry, C.TypeZeroTier, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ZeroTierEndpointOptions) (adapter.Endpoint, error) {
				result, err := NewEndpoint(ctx, router, logger, tag, options)
				if err != nil {
					return nil, err
				}
				ep = result.(*Endpoint)
				peerNode, listener, sent := newTCPTestPeer(t, ep, true)
				node, tcpSent = peerNode, sent
				node.config = &zt.VirtualNetworkConfig{Status: test.status}
				if test.status == zt.NetworkStatusOK {
					node.config = &ready
				}
				node.joinHook = func(n *fakeNode) error {
					n.callbacks.VirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, n.config)
					ep.learnMAC(netip.MustParseAddr("192.0.2.2"), 0x020000000002)
					return n.callbacks.WirePacketSend(0, netip.MustParseAddrPort("192.0.2.3:9993"), []byte{1}, 0)
				}
				ep.newNode = func(callbacks zt.NodeCallbacks, _ *zt.NodeConfig) (zeroTierNode, error) {
					node.callbacks = callbacks
					return node, nil
				}
				ep.listenUDP = func() (udpPacketConn, error) { return &fakePacketConn{}, nil }
				server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if requests.Add(1) == 1 {
						requestSeen <- r.URL.Path
					}
					select {
					case <-allowResponse:
						w.WriteHeader(test.response)
						_, _ = io.WriteString(w, rules)
					case <-r.Context().Done():
					}
				})}
				go func() { _ = server.Serve(listener) }()
				t.Cleanup(func() { require.NoError(t, server.Close()) })
				return ep, nil
			})

			ctx = box.Context(ctx, inboundRegistry, outboundRegistry, endpointRegistry, dnsRegistry, boxService.NewRegistry(), certificate.NewRegistry())
			var initialPath string
			if test.seed {
				initialPath = filepath.Join(t.TempDir(), "seed.json")
				require.NoError(t, os.WriteFile(initialPath, []byte(rules), 0o600))
			}
			config := fmt.Sprintf(`{
				"log":{"disabled":true},
				"endpoints":[{"type":"zerotier","tag":"zt","network_id":"0123456789abcdef","storage_path":%q}],
				"inbounds":[{"type":"tun","tag":"tun"}],
				"outbounds":[{"type":"direct","tag":"direct"}],
				"route":{"rules":[{"rule_set":"private","outbound":"direct"}],"rule_set":[{
					"type":"remote","tag":"private","format":"source","url":%q,
					"initial_path":%q,"http_client":{"detour":"zt","version":1}
				}]}
			}`, t.TempDir(), ruleURL, initialPath)
			var options option.Options
			require.NoError(t, singJSON.UnmarshalContext(ctx, []byte(config), &options))
			if test.cache {
				cacheOptions := &option.CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "cache.db")}
				cacheLogger := log.NewNOPFactory().Logger()
				seedCache := cachefile.New(ctx, cacheLogger, *cacheOptions)
				cacheScope := adapter.NewScope(ctx, cacheLogger)
				require.NoError(t, seedCache.Start(adapter.StartStateInitialize, cacheScope))
				urlHash := sha256.Sum256([]byte(ruleURL))
				require.NoError(t, seedCache.SaveRuleSet("private", &adapter.SavedBinary{Content: []byte(rules), URLHash: urlHash[:], LastUpdated: time.Now()}))
				require.NoError(t, cacheScope.Close())
				options.Experimental = &option.ExperimentalOptions{CacheFile: cacheOptions}
			}
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			startResult := make(chan error, 1)
			go func() {
				defer close(startResult)
				startResult <- instance.Start()
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-startResult:
					require.NoError(t, instance.Close())
				case <-time.After(2 * time.Second):
					t.Error("box.Start did not finish after cancellation")
				}
			})
			startError := func() error {
				t.Helper()
				select {
				case err := <-startResult:
					return err
				case <-time.After(2 * time.Second):
					t.Fatal("box.Start did not return")
					return nil
				}
			}
			assertStarted := func() {
				t.Helper()
				require.NoError(t, startError())
				require.Empty(t, progress.Stage())
				require.True(t, channelClosed(tunStarted), "TUN did not start")
				loaded, ok := instance.Router().RuleSet("private")
				require.True(t, ok)
				require.True(t, loaded.Match(&adapter.InboundContext{Domain: "overlay.example"}))
			}
			if test.seed || test.cache {
				assertStarted()
				require.Zero(t, requests.Load())
				require.False(t, channelClosed(tcpSent))
				return
			}

			if test.status != zt.NetworkStatusOK {
				require.Eventually(t, func() bool { return progress.Stage() == "waiting-zerotier-authorization" }, 2*time.Second, time.Millisecond)
				require.False(t, channelClosed(tunStarted))
				require.False(t, channelClosed(tcpSent))
				_, err := ep.DialContext(ctx, "tcp", M.ParseSocksaddr("192.0.2.2:8080"))
				require.ErrorContains(t, err, test.status.String(), "ordinary dials must not wait")
			}
			if test.cancel {
				cancel()
				require.ErrorIs(t, startError(), context.Canceled)
				require.Empty(t, progress.Stage())
				require.False(t, channelClosed(tunStarted))
				require.False(t, channelClosed(tcpSent))
				require.True(t, node.closed.Load())
				return
			}
			var stackBeforeAuthorization *stack.Stack
			if test.status != zt.NetworkStatusOK {
				stackBeforeAuthorization = ep.ipStack
				node.configMu.Lock()
				node.config = &ready
				node.configMu.Unlock()
				require.Zero(t, node.callbacks.VirtualNetworkConfig(ep.networkID, zt.VirtualNetworkConfigOperationConfigUpdate, &ready))
				ep.learnMAC(netip.MustParseAddr("192.0.2.2"), 0x020000000002)
			}
			select {
			case path := <-requestSeen:
				require.Equal(t, "/rules.json", path)
			case <-ctx.Done():
				t.Fatal("endpoint did not send the HTTP request")
			}
			if stackBeforeAuthorization != nil {
				require.Same(t, stackBeforeAuthorization, ep.ipStack)
			}
			require.Equal(t, "loading-rule-sets", progress.Stage())
			require.False(t, channelClosed(tunStarted))
			close(allowResponse)
			if test.response == http.StatusOK {
				assertStarted()
			} else {
				require.ErrorContains(t, startError(), "403 Forbidden")
				require.False(t, channelClosed(tunStarted))
			}
			require.EqualValues(t, 1, requests.Load())
		})
	}
}

func TestZeroTierRuleSetDialHonorsDetachedRequestCancellation(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	t.Cleanup(func() { require.NoError(t, ep.Close()) })
	_, err := ep.applyVirtualNetworkConfig(zt.VirtualNetworkConfigOperationConfigUpdate, &zt.VirtualNetworkConfig{Status: zt.NetworkStatusAccessDenied})
	require.NoError(t, err)
	require.NoError(t, ep.createStack())
	progress := new(adapter.RuleSetStartup)
	defer progress.BeginLoading()()
	requestCtx, cancel := context.WithCancel(service.ContextWithPtr(context.Background(), progress))
	defer cancel()
	dialCtx := context.WithoutCancel(adapter.ContextWithRuleSetStartupRequest(requestCtx))
	dialResult := make(chan error, 1)
	go func() {
		packet, err := ep.ListenPacket(dialCtx, M.ParseSocksaddr("192.0.2.2:443"))
		if packet != nil {
			_ = packet.Close()
		}
		dialResult <- err
	}()
	require.Eventually(t, func() bool { return progress.Stage() == "waiting-zerotier-authorization" }, time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-dialResult:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("dial remained blocked after the original request was canceled")
	}
	require.Equal(t, "loading-rule-sets", progress.Stage())
	require.False(t, ep.closed.Load())
}

type ruleSetStartupInbound struct {
	inbound.Adapter
	started chan struct{}
}

func (i *ruleSetStartupInbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		close(i.started)
	}
	return nil
}

func channelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
