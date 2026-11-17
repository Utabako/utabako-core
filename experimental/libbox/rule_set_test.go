package libbox

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func ruleSetTestWorkingPath(t *testing.T) string {
	t.Helper()
	previous := sWorkingPath
	sWorkingPath = t.TempDir()
	t.Cleanup(func() { sWorkingPath = previous })
	return sWorkingPath
}

func ruleSetTestConfig(url, extra string) string {
	return fmt.Sprintf(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"rule_set":"test","outbound":"direct"}],"rule_set":[{"type":"remote","tag":"test","format":"source","url":%q%s}]}}`, url, extra)
}

func preparedRuleSets(t *testing.T, config string) []option.RuleSet {
	t.Helper()
	options, err := parseConfig(baseContext(nil), config)
	require.NoError(t, err)
	return options.Route.RuleSet
}

func TestPrepareRuleSetsOfflineRemoteStart(t *testing.T) {
	ruleSetTestWorkingPath(t)
	for _, format := range []string{C.RuleSetFormatSource, C.RuleSetFormatBinary} {
		t.Run(format, func(t *testing.T) {
			var requests atomic.Int32
			contents := make(map[string][]byte)
			for _, tag := range []string{"first", "second"} {
				content := []byte(fmt.Sprintf(`{"version":4,"rules":[{"domain":[%q]}]}`, tag+".example"))
				if format == C.RuleSetFormatBinary {
					plain, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
					require.NoError(t, err)
					var binary bytes.Buffer
					require.NoError(t, srs.Write(&binary, plain.Options, C.RuleSetVersion4))
					content = binary.Bytes()
				}
				contents[tag] = content
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = w.Write(contents[r.URL.Query().Get("tag")])
			}))
			defer server.Close()
			url := server.URL + "/rules?tag={tag}"
			clientOption := ""
			if format == C.RuleSetFormatBinary {
				clientOption = `,"http_client":"public-rule-sources"`
			}
			config := fmt.Sprintf(`{
				"log":{"disabled":false,"timestamp":false},
				"dns":{"servers":[],"rules":[],"disable_cache":false},
				"http_clients":[{"tag":"managed-rule-sources","detour":"zt-ep"},{"tag":"public-rule-sources","detour":"\ud83d\ude80 节点选择"}],
				"outbounds":[{"type":"direct","tag":"direct","tcp_fast_open":false},{"type":"socks","tag":"unused","server":"127.0.0.1","server_port":1080}],
				"route":{"default_http_client":"managed-rule-sources","rules":[{"rule_set":["first","second"],"outbound":"direct"}],"rule_set":[{"type":"remote","tag":["first","second"],"format":%q,"url":%q,"update_interval":"3h","initial_path":""%s}],"auto_detect_interface":false},
				"experimental":{"cache_file":{"enabled":false,"store_fakeip":false}}
			}`, format, url, clientOption)
			prepared, err := PrepareRuleSets(config)
			require.NoError(t, err)
			require.EqualValues(t, 2, requests.Load())
			sets := preparedRuleSets(t, prepared.Value)
			require.Len(t, sets, 2)
			for i, tag := range []string{"first", "second"} {
				require.Equal(t, []string{tag}, []string(sets[i].Tag))
				require.Equal(t, C.RuleSetTypeRemote, sets[i].Type)
				require.Equal(t, url, sets[i].RemoteOptions.URL)
				if format == C.RuleSetFormatBinary {
					require.Equal(t, "public-rule-sources", sets[i].RemoteOptions.HTTPClient.Tag)
				} else {
					require.Nil(t, sets[i].RemoteOptions.HTTPClient)
				}
				require.Equal(t, filepath.Join(sWorkingPath, "rule-set-seeds"), filepath.Dir(sets[i].RemoteOptions.InitialPath))
				require.FileExists(t, sets[i].RemoteOptions.InitialPath)
			}
			var before, after map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(config), &before))
			require.NoError(t, json.Unmarshal([]byte(prepared.Value), &after))
			for _, key := range []string{"log", "dns", "outbounds", "experimental", "http_clients"} {
				require.JSONEq(t, string(before[key]), string(after[key]))
			}
			var routeBefore, routeAfter map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(before["route"], &routeBefore))
			require.NoError(t, json.Unmarshal(after["route"], &routeAfter))
			delete(routeBefore, "rule_set")
			delete(routeAfter, "rule_set")
			require.Equal(t, routeBefore, routeAfter)

			// No source server, no cache.db, no started outbound/VPN. Exercise
			// the actual RemoteRuleSet and HTTP manager, not a replacement loader.
			server.Close()
			ctx, cancel := context.WithCancel(baseContext(nil))
			defer cancel()
			ctx = service.ContextWith[adapter.PlatformInterface](ctx, (*platformInterfaceStub)(nil))
			options, err := parseConfig(ctx, prepared.Value)
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			defer instance.Close()
			startContext := adapter.NewHTTPStartContext()
			defer startContext.Close()
			for _, tag := range []string{"first", "second"} {
				remote, exists := instance.Router().RuleSet(tag)
				require.True(t, exists)
				defer remote.Close()
				require.NoError(t, remote.StartContext(ctx, startContext))
				require.True(t, remote.Match(&adapter.InboundContext{Domain: tag + ".example"}))
				require.False(t, remote.Match(&adapter.InboundContext{Domain: "unrelated.example"}))
			}
			require.EqualValues(t, 2, requests.Load())
			// Editing/renaming the prepared profile must work offline unchanged.
			repeated, err := PrepareRuleSets(prepared.Value)
			require.NoError(t, err)
			require.Equal(t, prepared.Value, repeated.Value)
		})
	}
}

func TestPrepareRuleSetsFailurePreservesSeeds(t *testing.T) {
	workingPath := ruleSetTestWorkingPath(t)
	good := `{"version":4,"rules":[{"domain":"kept.example"}]}`
	var badContent string
	var badStatus int
	var badRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good":
			_, _ = w.Write([]byte(good))
		case "/changed":
			_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":"new.example"}]}`))
		default:
			badRequests.Add(1)
			w.WriteHeader(badStatus)
			_, _ = w.Write([]byte(badContent))
		}
	}))
	defer server.Close()
	original, err := PrepareRuleSets(ruleSetTestConfig(server.URL+"/good", ""))
	require.NoError(t, err)
	oldPath := preparedRuleSets(t, original.Value)[0].RemoteOptions.InitialPath
	for _, testCase := range []struct {
		name, body, format, want string
		status                   int
	}{
		{"HTTP error", "denied", "source", "403", http.StatusForbidden},
		{"malformed source", "{", "source", "unexpected", http.StatusOK},
		{"invalid CIDR", `{"version":4,"rules":[{"ip_cidr":"bad-prefix"}]}`, "source", "bad-prefix", http.StatusOK},
		{"invalid regex", `{"version":4,"rules":[{"domain_regex":"["}]}`, "source", "error parsing regexp", http.StatusOK},
		{"unsupported source version", `{"version":99,"rules":[{"domain":"example.org"}]}`, "source", "version", http.StatusOK},
		{"malformed SRS", "SRS", "binary", "EOF", http.StatusOK},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			badContent, badStatus = testCase.body, testCase.status
			badRequests.Store(0)
			input := fmt.Sprintf(`{"route":{"rule_set":[{"type":"remote","tag":"new","format":"source","url":%q},{"type":"remote","tag":"broken","format":%q,"url":%q}]}}`, server.URL+"/changed", testCase.format, server.URL+"/bad")
			prepared, err := PrepareRuleSets(input)
			require.Nil(t, prepared)
			require.ErrorContains(t, err, testCase.want)
			require.ErrorContains(t, err, "broken")
			require.ErrorContains(t, err, server.URL+"/bad")
			require.EqualValues(t, 1, badRequests.Load(), "no retry or fallback")
			content, err := os.ReadFile(oldPath)
			require.NoError(t, err)
			require.Equal(t, good, string(content))
			files, err := os.ReadDir(filepath.Join(workingPath, "rule-set-seeds"))
			require.NoError(t, err)
			require.Len(t, files, 1, "failed preparation publishes no new seed and cleans staging")
			require.Equal(t, filepath.Base(oldPath), files[0].Name())
		})
	}
}

func TestPrepareRuleSetsValidatesMetadataAndReferences(t *testing.T) {
	ruleSetTestWorkingPath(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"ip_cidr":"192.0.2.0/24"}]}`))
	}))
	defer server.Close()
	for _, testCase := range []struct{ name, dns, rules, want string }{
		{"DNS content metadata", `"dns":{"servers":[{"type":"hosts","tag":"dns"}],"rules":[{"query_type":"A","rule_set":"test","server":"dns"}]},`, `[]`, "Legacy Address Filter"},
		{"missing route reference", "", `[{"rule_set":"missing","action":"reject"}]`, "rule-set not found: missing"},
		{"missing DNS reference", `"dns":{"servers":[{"type":"hosts","tag":"dns"}],"rules":[{"rule_set":"missing","server":"dns"}]},`, `[]`, "rule-set not found: missing"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := fmt.Sprintf(`{%s"route":{"rules":%s,"rule_set":[{"type":"remote","tag":"test","format":"source","url":%q}]}}`, testCase.dns, testCase.rules, server.URL)
			if testCase.name == "DNS content metadata" {
				require.NoError(t, CheckConfig(config), "ordinary CheckConfig cannot see remote content")
			}
			result, err := PrepareRuleSets(config)
			require.Nil(t, result)
			require.ErrorContains(t, err, testCase.want)
		})
	}
}

func TestPrepareRuleSetsHonorsExplicitInitialPath(t *testing.T) {
	workingPath := ruleSetTestWorkingPath(t)
	for _, tag := range []string{"first", "second"} {
		require.NoError(t, os.WriteFile(filepath.Join(workingPath, tag+".json"), []byte(`{"version":4,"rules":[{"domain":"local.example"}]}`), 0o600))
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	config := fmt.Sprintf(`{"route":{"rule_set":[{"type":"remote","tag":["first","second"],"format":"source","url":%q,"initial_path":"{tag}.json","http_client":{"headers":{"Authorization":"secret"}}}]}}`, server.URL+"/{tag}")
	result, err := PrepareRuleSets(config)
	require.NoError(t, err)
	require.Equal(t, config, result.Value)
	require.Zero(t, requests.Load())
	require.NoError(t, os.Remove(filepath.Join(workingPath, "second.json")))
	result, err = PrepareRuleSets(config)
	require.Nil(t, result)
	require.ErrorContains(t, err, "second")
	require.ErrorContains(t, err, "no such file")
	require.Zero(t, requests.Load(), "explicit initial_path failure must not download replacement")
}

func TestPrepareRuleSetsEffectiveHTTPPolicy(t *testing.T) {
	ruleSetTestWorkingPath(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":"example.org"}]}`))
	}))
	defer server.Close()
	for _, testCase := range []struct{ name, clients, route, remote, certificates, want string }{
		{"inline headers", "", "", `,"http_client":{"headers":{"Authorization":"secret"}}`, "", "custom http_client"},
		{"shared default headers", `"http_clients":[{"tag":"auth","headers":{"Authorization":"secret"}}],`, "", "", "", "custom http_client"},
		{"selected default headers", `"http_clients":[{"tag":"plain"},{"tag":"auth","headers":{"Authorization":"secret"}}],`, `"default_http_client":"auth",`, "", "", "custom http_client"},
		{"named TLS", `"http_clients":[{"tag":"tls","tls":{"enabled":true,"server_name":"special.example"}}],`, "", `,"http_client":"tls"`, "", "custom http_client"},
		{"missing named", "", "", `,"http_client":"missing"`, "", "http_client not found"},
		{"actual managed default detour", `"http_clients":[{"tag":"managed-rule-sources","detour":"zt-ep"},{"tag":"public-rule-sources","detour":"\ud83d\ude80 节点选择"}],`, `"default_http_client":"managed-rule-sources",`, "", "", ""},
		{"actual public explicit detour", `"http_clients":[{"tag":"managed-rule-sources","detour":"zt-ep"},{"tag":"public-rule-sources","detour":"\ud83d\ude80 节点选择"}],`, `"default_http_client":"managed-rule-sources",`, `,"http_client":"public-rule-sources"`, "", ""},
		{"unrelated shared client", `"http_clients":[{"tag":"plain"},{"tag":"unused","headers":{"Authorization":"secret"}}],`, "", "", "", ""},
		{"detour uses current network", `"http_clients":[{"tag":"unused","headers":{"Authorization":"secret"}}],`, "", `,"download_detour":"not-started"`, `"certificate":{"store":"none"},`, ""},
		{"empty HTTP options", "", "", `,"http_client":{}`, "", ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			requests.Store(0)
			config := fmt.Sprintf(`{%s%s"route":{%s"rule_set":[{"type":"remote","tag":"test","format":"source","url":%q%s}]}}`, testCase.clients, testCase.certificates, testCase.route, server.URL, testCase.remote)
			result, err := PrepareRuleSets(config)
			if testCase.want != "" {
				require.Nil(t, result)
				require.ErrorContains(t, err, testCase.want)
				require.ErrorContains(t, err, server.URL)
				require.Zero(t, requests.Load())
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				require.EqualValues(t, 1, requests.Load())
			}
		})
	}
}

func TestPrepareRuleSetsConcurrentImmutableSeeds(t *testing.T) {
	workingPath := ruleSetTestWorkingPath(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":"example.org"}]}`))
	}))
	defer server.Close()
	config := ruleSetTestConfig(server.URL, "")
	var wg sync.WaitGroup
	results := make([]*StringBox, 4)
	errors := make([]error, len(results))
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errors[i] = PrepareRuleSets(config)
		}()
	}
	wg.Wait()
	for i := range results {
		require.NoError(t, errors[i])
		require.Equal(t, results[0].Value, results[i].Value)
	}
	files, err := os.ReadDir(filepath.Join(workingPath, "rule-set-seeds"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.False(t, strings.HasPrefix(files[0].Name(), ".prepare-"))
	seed := preparedRuleSets(t, results[0].Value)[0].RemoteOptions.InitialPath
	seedContent, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.Equal(t, `{"version":4,"rules":[{"domain":"example.org"}]}`, string(seedContent))
	before, err := os.Stat(seed)
	require.NoError(t, err)
	repeated, err := PrepareRuleSets(config)
	require.NoError(t, err)
	require.Equal(t, results[0].Value, repeated.Value)
	after, err := os.Stat(seed)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after), "same-hash reuse must not replace an existing seed")
	// A preexisting corrupt seed is never silently overwritten.
	require.NoError(t, os.WriteFile(seed, []byte("corrupt"), 0o600))
	result, err := PrepareRuleSets(config)
	require.Nil(t, result)
	require.ErrorContains(t, err, "content mismatch")
	content, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.Equal(t, "corrupt", string(content))
}

func TestPrepareRuleSetsPreservesRawConfigFacts(t *testing.T) {
	workingPath := ruleSetTestWorkingPath(t)
	local := `{"version":4,"rules":[{"domain":"local.example"}]}`
	require.NoError(t, os.WriteFile(filepath.Join(workingPath, "local.json"), []byte(local), 0o600))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "password" {
			http.Error(w, "missing original URL authorization", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":"remote.example"}]}`))
	}))
	defer server.Close()
	url := strings.Replace(server.URL, "http://", "http://user:password@", 1) + "/source.json"
	config := fmt.Sprintf(`{
		// Preserve explicit values rather than round-tripping typed Options.
		"$schema":"https://example.org/schema.json",
		"log":{"disabled":false,"timestamp":false},
		"outbounds":[{"type":"direct","tag":"direct","tcp_fast_open":false}],
		"route":{"rules":[],"rule_set":[
			{"type":"inline","tag":"inline","rules":[{"domain":"inline.example","invert":false}]},
			{"type":"local","tag":["local"],"path":"local.json"},
			{"type":"remote","tag":["../outside"],"url":%q,"http_client":{},"update_interval":"24h"}
		]}
	}`, url)
	result, err := PrepareRuleSets(config)
	require.NoError(t, err)
	sets := preparedRuleSets(t, result.Value)
	require.Len(t, sets, 3)
	require.Equal(t, C.RuleSetFormatSource, sets[2].Format, "infer format from original URL")
	require.Equal(t, filepath.Join(workingPath, "rule-set-seeds"), filepath.Dir(sets[2].RemoteOptions.InitialPath), "tags must not become paths")
	var root, route map[string]json.RawMessage
	var rawSets []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(result.Value), &root))
	require.NoError(t, json.Unmarshal(root["route"], &route))
	require.NoError(t, json.Unmarshal(route["rule_set"], &rawSets))
	require.JSONEq(t, `{"disabled":false,"timestamp":false}`, string(root["log"]))
	require.Equal(t, json.RawMessage(`[]`), route["rules"])
	require.Equal(t, json.RawMessage(`["../outside"]`), rawSets[2]["tag"])
	require.Equal(t, json.RawMessage(`{}`), rawSets[2]["http_client"])
	require.Equal(t, json.RawMessage(`"24h"`), rawSets[2]["update_interval"])
	require.NotContains(t, rawSets[2], "format", "do not materialize inferred defaults")
	require.Equal(t, json.RawMessage(`"inline"`), rawSets[0]["type"])
	require.Contains(t, string(rawSets[0]["rules"]), `"invert":false`)
	require.Equal(t, json.RawMessage(`["local"]`), rawSets[1]["tag"])
	require.Equal(t, json.RawMessage(`"local.json"`), rawSets[1]["path"])
}

func TestPrepareRuleSetsBoundsStalledDownloads(t *testing.T) {
	workingPath := ruleSetTestWorkingPath(t)
	good := `{"version":4,"rules":[{"domain":"kept.example"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/good" {
			_, _ = w.Write([]byte(good))
			return
		}
		if r.URL.Path == "/body" {
			_, _ = w.Write([]byte(`{"version":4,`))
			w.(http.Flusher).Flush()
		}
		// A real peer that never supplies headers or finishes the body.
		// Client timeout must cancel the request rather than retry it.
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	original, err := PrepareRuleSets(ruleSetTestConfig(server.URL+"/good", ""))
	require.NoError(t, err)
	seedPath := preparedRuleSets(t, original.Value)[0].RemoteOptions.InitialPath
	t.Cleanup(func() {
		files, err := os.ReadDir(filepath.Join(workingPath, "rule-set-seeds"))
		require.NoError(t, err)
		require.Len(t, files, 1, "both timed-out preparations clean their staging files")
		require.Equal(t, filepath.Base(seedPath), files[0].Name())
	})
	for _, path := range []string{"/headers", "/body"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			result, err := PrepareRuleSets(ruleSetTestConfig(server.URL+path, ""))
			require.Nil(t, result)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.ErrorContains(t, err, server.URL+path)
			require.ErrorContains(t, err, "rule-set[test]")
			content, err := os.ReadFile(seedPath)
			require.NoError(t, err)
			require.Equal(t, good, string(content))
		})
	}
}

func TestPrepareRuleSetsRedirectCertificates(t *testing.T) {
	if redirectURL := os.Getenv("LIBBOX_RULE_SET_REDIRECT_TEST_URL"); redirectURL != "" {
		workingPath := ruleSetTestWorkingPath(t)
		config := ruleSetTestConfig(redirectURL, "")
		// Prove the HTTPS target is trusted and reachable through the actual
		// SDK transport; a self-signed handshake failure is not this regression.
		good, err := PrepareRuleSets(config)
		require.NoError(t, err)
		seedPath := preparedRuleSets(t, good.Value)[0].RemoteOptions.InitialPath
		seedContent, err := os.ReadFile(seedPath)
		require.NoError(t, err)
		config = `{"certificate":{"store":"none"},` + strings.TrimPrefix(config, "{")
		result, err := PrepareRuleSets(config)
		require.Nil(t, result, "HTTP redirects must not bypass the configured certificate policy")
		require.ErrorContains(t, err, "does not support custom certificate options")
		require.ErrorContains(t, err, redirectURL)
		require.ErrorContains(t, err, "rule-set[test]")
		content, err := os.ReadFile(seedPath)
		require.NoError(t, err)
		require.Equal(t, seedContent, content)
		files, err := os.ReadDir(filepath.Join(workingPath, "rule-set-seeds"))
		require.NoError(t, err)
		require.Len(t, files, 1)
		require.Equal(t, filepath.Base(seedPath), files[0].Name())
		return
	}
	var targetRequests atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"domain":"example.org"}]}`))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "trusted.pem")
	require.NoError(t, os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: target.Certificate().Raw,
	}), 0o600))
	executable, err := os.Executable()
	require.NoError(t, err)
	// System roots are cached process-wide. A separate test process supplies
	// real trust without mutating production globals or replacing the client.
	command := exec.Command(executable, "-test.run=^TestPrepareRuleSetsRedirectCertificates$", "-test.count=1")
	command.Env = append(os.Environ(),
		"LIBBOX_RULE_SET_REDIRECT_TEST_URL="+redirect.URL,
		"SSL_CERT_FILE="+certificatePath,
		"SSL_CERT_DIR="+directory,
	)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.EqualValues(t, 1, targetRequests.Load(), "only the control request may reach HTTPS")
}

func TestPrepareRuleSetsKeepsRedirectLimit(t *testing.T) {
	ruleSetTestWorkingPath(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer server.Close()
	result, err := PrepareRuleSets(ruleSetTestConfig(server.URL, ""))
	require.Nil(t, result)
	require.ErrorContains(t, err, "stopped after 10 redirects")
	require.EqualValues(t, 10, requests.Load())
}
