//go:build with_zerotier && with_gvisor

package libbox

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

const zeroTierRuleSetEndpoint = `"endpoints":[{"type":"zerotier","tag":"private-network","network_id":"8056c2e21c000001"}]`

func TestPrepareRuleSetsDefersExplicitZeroTier(t *testing.T) {
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

	for _, test := range []struct{ name, clients, route, remote string }{
		{"inline", "", "", `,"http_client":{"detour":"private-network","headers":{"Authorization":"private"}}`},
		{"named", `,"http_clients":[{"tag":"public"},{"tag":"private","detour":"private-network"}]`, "", `,"http_client":"private"`},
		{"first client", `,"http_clients":[{"tag":"private","detour":"private-network"}]`, "", ""},
		{"configured default", `,"http_clients":[{"tag":"public"},{"tag":"private","detour":"private-network"}]`, `"default_http_client":"private",`, ""},
		{"legacy detour", "", "", `,"download_detour":"private-network"`},
		{"explicit final", "", `"final":"private-network",`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := fmt.Sprintf(`{%s%s,"route":{%s"rules":[{"rule_set":["first","second"],"action":"reject"}],"rule_set":[{"type":"remote","tag":["first","second"],"format":"source","url":%q%s}]}}`, zeroTierRuleSetEndpoint, test.clients, test.route, server.URL+"/{tag}", test.remote)
			result, err := PrepareRuleSets(config)
			require.NoError(t, err)
			require.Equal(t, config, result.Value)
			require.Zero(t, privateRequests.Load())
			require.NoDirExists(t, filepath.Join(workingPath, "zerotier"))
			require.NoDirExists(t, filepath.Join(workingPath, "rule-set-seeds"))
		})
	}

	config := fmt.Sprintf(`{%s,"http_clients":[{"tag":"private","detour":"private-network"},{"tag":"public"}],"outbounds":[{"type":"selector","tag":"pick","outbounds":["private-network"]}],"route":{"rule_set":[{"type":"remote","tag":"private","format":"source","url":%q},{"type":"remote","tag":"public","format":"source","url":%q,"http_client":"public"},{"type":"remote","tag":"selector","format":"source","url":%q,"http_client":{"detour":"pick"}}]}}`, zeroTierRuleSetEndpoint, server.URL+"/private", server.URL+"/public", server.URL+"/public")
	result, err := PrepareRuleSets(config)
	require.NoError(t, err)
	sets := preparedRuleSets(t, result.Value)
	require.Empty(t, sets[0].RemoteOptions.InitialPath)
	require.FileExists(t, sets[1].RemoteOptions.InitialPath)
	require.FileExists(t, sets[2].RemoteOptions.InitialPath)
	require.Zero(t, privateRequests.Load())
	require.EqualValues(t, 2, publicRequests.Load())
}

func TestPrepareRuleSetsValidatesDeferredZeroTier(t *testing.T) {
	ruleSetTestWorkingPath(t)
	for _, test := range []struct{ name, url, httpClient, rules, want string }{
		{"URL", "file:///rules.json", `{"detour":"private-network"}`, `[]`, "expected an HTTP or HTTPS URL with a host"},
		{"transport", "http://10.20.30.40/rules.json", `{"detour":"private-network","domain_resolver":"missing"}`, `[]`, "domain resolver not found: missing"},
		{"rule reference", "http://10.20.30.40/rules.json", `{"detour":"private-network"}`, `[{"rule_set":"missing","action":"reject"}]`, "rule-set not found: missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := fmt.Sprintf(`{%s,"route":{"rules":%s,"rule_set":[{"type":"remote","tag":"private","format":"source","url":%q,"http_client":%s}]}}`, zeroTierRuleSetEndpoint, test.rules, test.url, test.httpClient)
			result, err := PrepareRuleSets(config)
			require.Nil(t, result)
			require.ErrorContains(t, err, test.want)
		})
	}
}
