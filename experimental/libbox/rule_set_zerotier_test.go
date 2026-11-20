//go:build with_zerotier && with_gvisor

package libbox

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/stretchr/testify/require"
)

const zeroTierRuleSetEndpoint = `"endpoints":[{"type":"zerotier","tag":"private-network","network_id":"8056c2e21c000001"}]`

func TestPrepareRuleSetsDefersEffectiveZeroTierClient(t *testing.T) {
	workingPath := ruleSetTestWorkingPath(t)
	var privateRequests, publicRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public" {
			privateRequests.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		publicRequests.Add(1)
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":"public.example"}]}`))
	}))
	defer server.Close()

	for _, testCase := range []struct{ name, clients, route, remote string }{
		{"inline", "", "", `,"http_client":{"detour":"private-network","headers":{"Authorization":"private"}}`},
		{"named", `,"http_clients":[{"tag":"public"},{"tag":"private","detour":"private-network"}]`, "", `,"http_client":"private"`},
		{"first client", `,"http_clients":[{"tag":"private","detour":"private-network"}]`, "", ""},
		{"configured default", `,"http_clients":[{"tag":"public"},{"tag":"private","detour":"private-network"}]`, `"default_http_client":"private",`, ""},
		{"legacy detour", "", "", `,"download_detour":"private-network"`},
		{"implicit client", "", `"final":"private-network",`, ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := fmt.Sprintf(`{%s%s,"route":{%s"rules":[{"rule_set":["first","second"],"action":"reject"}],"rule_set":[{"type":"remote","tag":["first","second"],"format":"source","url":%q%s}]}}`, zeroTierRuleSetEndpoint, testCase.clients, testCase.route, server.URL+"/{tag}", testCase.remote)
			result, err := PrepareRuleSets(config)
			require.NoError(t, err)
			require.Equal(t, config, result.Value, "the unseeded remote definition must be kept verbatim")
			require.Zero(t, privateRequests.Load())
			require.NoDirExists(t, filepath.Join(workingPath, "zerotier"), "preparation must not start the endpoint")
			require.NoDirExists(t, filepath.Join(workingPath, "rule-set-seeds"))
		})
	}

	config := fmt.Sprintf(`{%s,"http_clients":[{"tag":"private","detour":"private-network"},{"tag":"public"}],"route":{"rule_set":[{"type":"remote","tag":"private","format":"source","url":%q},{"type":"remote","tag":"public","format":"source","url":%q,"http_client":"public"}]}}`, zeroTierRuleSetEndpoint, server.URL+"/private", server.URL+"/public")
	result, err := PrepareRuleSets(config)
	require.NoError(t, err)
	sets := preparedRuleSets(t, result.Value)
	require.Len(t, sets, 2)
	require.Empty(t, sets[0].RemoteOptions.InitialPath)
	require.FileExists(t, sets[1].RemoteOptions.InitialPath)
	require.Zero(t, privateRequests.Load())
	require.EqualValues(t, 1, publicRequests.Load())
}

func TestPrepareRuleSetsValidatesDeferredZeroTierConfig(t *testing.T) {
	ruleSetTestWorkingPath(t)
	for _, testCase := range []struct{ name, url, httpClient, rules, want string }{
		{"URL", "file:///rules.json", `{"detour":"private-network"}`, `[]`, "expected an HTTP or HTTPS URL with a host"},
		{"transport", "http://10.20.30.40/rules.json", `{"detour":"private-network","domain_resolver":"missing"}`, `[]`, "domain resolver not found: missing"},
		{"rule reference", "http://10.20.30.40/rules.json", `{"detour":"private-network"}`, `[{"rule_set":"missing","action":"reject"}]`, "rule-set not found: missing"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := fmt.Sprintf(`{%s,"route":{"rules":%s,"rule_set":[{"type":"remote","tag":"private","format":"source","url":%q,"http_client":%s}]}}`, zeroTierRuleSetEndpoint, testCase.rules, testCase.url, testCase.httpClient)
			result, err := PrepareRuleSets(config)
			require.Nil(t, result)
			require.ErrorContains(t, err, testCase.want)
		})
	}
}

func TestPrepareRuleSetsUsesFreshSelectorChoice(t *testing.T) {
	const selector = `{"type":"selector","tag":"pick","outbounds":["system","private-network"],"default":"private-network"}`
	const direct = `{"type":"direct","tag":"system"}`
	for _, test := range []struct {
		name, outbounds, detour, cachePath string
		deferred                           bool
	}{
		{name: "configured default", outbounds: selector + "," + direct, detour: "pick", deferred: true},
		{name: "first member", outbounds: `{"type":"selector","tag":"pick","outbounds":["private-network","system"]},` + direct, detour: "pick", deferred: true},
		{name: "nested through implicit default outbound", outbounds: `{"type":"selector","tag":"outer","outbounds":["pick"]},` + selector + "," + direct, deferred: true},
		{name: "current member is direct", outbounds: `{"type":"selector","tag":"pick","outbounds":["private-network","system"],"default":"system"},` + direct, detour: "pick"},
		{name: "urltest remains dynamic", outbounds: `{"type":"urltest","tag":"pick","outbounds":["private-network","system"]},` + direct, detour: "pick"},
		{name: "existing default cache", outbounds: selector + "," + direct, detour: "pick", cachePath: "cache.db"},
		{name: "existing configured cache", outbounds: selector + "," + direct, detour: "pick", cachePath: "profile.db"},
		{name: "direct detour with existing cache", outbounds: direct, detour: "private-network", cachePath: "profile.db", deferred: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			workingPath := ruleSetTestWorkingPath(t)
			var cacheOptions string
			if test.cachePath != "" {
				ctx := filemanager.WithDefault(baseContext(nil), workingPath, workingPath, os.Getuid(), os.Getgid())
				logger := log.NewNOPFactory().Logger()
				scope := adapter.NewScope(ctx, logger)
				t.Cleanup(func() { require.NoError(t, scope.Close()) })
				var cacheConfig option.CacheFileOptions
				if test.cachePath != "cache.db" {
					cacheConfig.Path, cacheConfig.CacheID = test.cachePath, "profile"
					cacheOptions = fmt.Sprintf(`,"experimental":{"cache_file":{"path":%q,"cache_id":"profile"}}`, test.cachePath)
				}
				cache := cachefile.New(ctx, logger, cacheConfig)
				require.NoError(t, scope.Start(cache.Name(), cache, adapter.StartStateInitialize))
				require.NoError(t, cache.StoreSelected("pick", "system"))
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":"example.org"}]}`))
			}))
			defer server.Close()
			var remoteClient string
			if test.detour != "" {
				remoteClient = fmt.Sprintf(`,"http_client":{"detour":%q}`, test.detour)
			}
			config := fmt.Sprintf(`{%s,"outbounds":[%s]%s,"route":{"rule_set":[{"type":"remote","tag":"rules","format":"source","url":%q%s}]}}`, zeroTierRuleSetEndpoint, test.outbounds, cacheOptions, server.URL, remoteClient)
			result, err := PrepareRuleSets(config)
			require.NoError(t, err)
			if test.deferred {
				require.Equal(t, config, result.Value)
				require.Zero(t, requests.Load())
			} else {
				sets := preparedRuleSets(t, result.Value)
				require.FileExists(t, sets[0].RemoteOptions.InitialPath)
				require.EqualValues(t, 1, requests.Load())
			}
			require.NoDirExists(t, filepath.Join(workingPath, "zerotier"))
			if test.cachePath == "" {
				require.NoFileExists(t, filepath.Join(workingPath, "cache.db"))
			}
		})
	}
}
