package libbox

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

var ruleSetSeedPublishAccess sync.Mutex

// PrepareRuleSets validates a configuration and prepares immutable initial_path
// seeds for remote rule-sets over the current system network, without starting
// the prospective configuration. The caller must save the returned configuration
// only on success. Explicit initial_path values are validated, not replaced.
func PrepareRuleSets(configContent string) (*StringBox, error) {
	ctx, cancel := context.WithCancel(baseContext(nil))
	defer cancel()
	options, err := parseConfig(ctx, configContent)
	if err != nil {
		return nil, err
	}
	var rawConfig, rawRoute map[string]json.RawMessage
	var rawSets []json.RawMessage
	if options.Route != nil && len(options.Route.RuleSet) > 0 {
		if err = json.Unmarshal(options.RawMessage, &rawConfig); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(rawConfig["route"], &rawRoute); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(rawRoute["rule_set"], &rawSets); err != nil {
			return nil, err
		}
	}

	var client *httpClient
	var stagingPath string
	defer func() {
		if client != nil {
			client.Close()
		}
		if stagingPath != "" {
			os.RemoveAll(stagingPath)
		}
	}()
	// Files are published only after all content and config references validate.
	seeds := make(map[string]string) // final path -> staged path
	var preparedSets []json.RawMessage
	var validationSets []option.RuleSet
	var origins []string
	if options.Route != nil {
		for i, set := range options.Route.RuleSet {
			if set.Type != C.RuleSetTypeRemote {
				preparedSets = append(preparedSets, rawSets[i])
				validationSets = append(validationSets, set)
				continue
			}
			for _, tag := range set.Tag {
				url := strings.ReplaceAll(set.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag)
				origin := fmt.Sprintf("rule-set[%s] from %s", tag, url)
				origins = append(origins, origin)
				seedPath := set.RemoteOptions.InitialPath
				if seedPath == "" {
					if err = checkRuleSetBootstrapHTTP(options, set.RemoteOptions, url); err != nil {
						return nil, E.Cause(err, "prepare ", origin)
					}
					if stagingPath == "" {
						if sWorkingPath == "" {
							return nil, E.New("prepare ", origin, ": libbox working path is not configured")
						}
						seedDirectory, pathErr := filepath.Abs(filepath.Join(sWorkingPath, "rule-set-seeds"))
						if pathErr != nil {
							return nil, E.Cause(pathErr, "prepare ", origin)
						}
						if err = os.MkdirAll(seedDirectory, 0o700); err != nil {
							return nil, E.Cause(err, "prepare ", origin)
						}
						stagingPath, err = os.MkdirTemp(seedDirectory, ".prepare-")
						if err != nil {
							return nil, E.Cause(err, "prepare ", origin)
						}
						client = newHTTPClient()
						// Like libbox's F-Droid downloads, bound the entire
						// request, including a stalled response body.
						client.client.Timeout = 30 * time.Second
						client.client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
							// Installing CheckRedirect replaces net/http's default
							// policy, so retain its ten-request redirect limit.
							if len(via) >= 10 {
								return E.New("stopped after 10 redirects")
							}
							return checkRuleSetBootstrapCertificates(options.Certificate, request.URL.String())
						}
					}
					request := client.NewRequest()
					if err = request.SetURL(url); err != nil {
						return nil, E.Cause(err, "prepare ", origin)
					}
					response, requestErr := request.Execute()
					if requestErr != nil {
						return nil, E.Cause(requestErr, "prepare ", origin)
					}
					seedPath = filepath.Join(stagingPath, fmt.Sprint(len(validationSets)))
					if err = response.WriteTo(seedPath); err != nil {
						return nil, E.Cause(err, "prepare ", origin)
					}
					content, readErr := os.ReadFile(seedPath)
					if readErr != nil {
						return nil, E.Cause(readErr, "prepare ", origin)
					}
					extension := ".json"
					if set.Format == C.RuleSetFormatBinary {
						extension = ".srs"
					}
					name := fmt.Sprintf("%x%s", sha256.Sum256(content), extension)
					finalPath := filepath.Join(filepath.Dir(stagingPath), name)
					seeds[finalPath] = seedPath
					// Patch raw JSON, not typed Options: marshaling Options would
					// canonicalize unrelated explicit values and defaults.
					var rawSet map[string]json.RawMessage
					if err = json.Unmarshal(rawSets[i], &rawSet); err != nil {
						return nil, err
					}
					rawSet["initial_path"], _ = json.Marshal(finalPath)
					if len(set.Tag) > 1 {
						// Keep the original URL template; core still resolves it
						// using this tag during normal remote refreshes.
						rawSet["tag"], _ = json.Marshal(tag)
					}
					prepared, marshalErr := json.Marshal(rawSet)
					if marshalErr != nil {
						return nil, marshalErr
					}
					preparedSets = append(preparedSets, prepared)
				} else if tag == set.Tag[0] {
					preparedSets = append(preparedSets, rawSets[i])
				}
				localSet := option.RuleSet{
					Type: C.RuleSetTypeLocal, Tag: []string{tag}, Format: set.Format,
					LocalOptions: option.LocalRuleSet{Path: seedPath},
				}
				// Reuse native source/SRS decoding and headless-rule construction.
				loaded, loadErr := rule.NewLocalRuleSet(ctx, log.NewNOPFactory().Logger(), tag, localSet)
				if loadErr != nil {
					return nil, E.Cause(loadErr, "prepare ", origin)
				}
				loaded.Close()
				validationSets = append(validationSets, localSet)
			}
		}
		validationRoute := *options.Route
		validationRoute.RuleSet = validationSets
		options.Route = &validationRoute
	}
	// Local construction exposes actual rule metadata to the config's DNS and
	// route validators. Returned rules remain remote; no VPN or proxy is started.
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, (*platformInterfaceStub)(nil))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, E.Cause(err, "validate prepared config (", strings.Join(origins, ", "), ")")
	}
	defer instance.Close()
	// Box.Close before Start has no registered rule-set cleanup callbacks.
	for _, set := range validationSets {
		for _, tag := range set.Tag {
			if loaded, exists := instance.Router().RuleSet(tag); exists {
				defer loaded.Close()
			}
		}
	}
	for i, configRule := range instance.Router().Rules() {
		// Rule.Start resolves references only; it does not start the router.
		err = configRule.Start()
		configRule.Close()
		if err != nil {
			return nil, E.Cause(err, "validate route rule[", i, "]")
		}
	}
	if len(seeds) == 0 {
		return wrapString(configContent), nil
	}
	rawRoute["rule_set"], err = json.Marshal(preparedSets)
	if err != nil {
		return nil, err
	}
	rawConfig["route"], err = json.Marshal(rawRoute)
	if err != nil {
		return nil, err
	}
	preparedConfig, err := json.Marshal(rawConfig)
	if err != nil {
		return nil, err
	}
	// This process owns writes to app-private seeds; the running core only
	// reads them. Serialize check-and-rename, not downloads or validation.
	ruleSetSeedPublishAccess.Lock()
	defer ruleSetSeedPublishAccess.Unlock()
	for finalPath, stagedPath := range seeds {
		oldContent, readErr := os.ReadFile(finalPath)
		if readErr == nil {
			if fmt.Sprintf("%x", sha256.Sum256(oldContent)) != strings.TrimSuffix(filepath.Base(finalPath), filepath.Ext(finalPath)) {
				return nil, E.New("existing rule-set seed content mismatch: ", finalPath)
			}
			continue
		}
		if !os.IsNotExist(readErr) {
			return nil, E.Cause(readErr, "read existing rule-set seed ", finalPath)
		}
		// Staging is on the same filesystem. Rename publishes the complete
		// file atomically without requiring Android's denied hard-link API.
		if err = os.Rename(stagedPath, finalPath); err != nil {
			return nil, E.Cause(err, "publish rule-set seed ", finalPath)
		}
	}
	return wrapString(string(preparedConfig)), nil
}

func checkRuleSetBootstrapHTTP(options option.Options, remote option.RemoteRuleSet, url string) error {
	var transport option.HTTPClientOptions
	if remote.HTTPClient != nil && !remote.HTTPClient.IsEmpty() {
		if remote.DownloadDetour != "" { //nolint:staticcheck
			return E.New("http_client is conflict with deprecated download_detour field")
		}
		transport = *remote.HTTPClient
	} else if remote.DownloadDetour == "" { //nolint:staticcheck
		if options.Route != nil {
			transport.Tag = options.Route.DefaultHTTPClient
		}
		if transport.Tag == "" && len(options.HTTPClients) > 0 {
			transport.Tag = options.HTTPClients[0].Tag
		}
	}
	if transport.Tag != "" {
		found := false
		for _, client := range options.HTTPClients {
			if client.Tag == transport.Tag {
				transport = client.Options()
				found = true
				break
			}
		}
		if !found {
			return E.New("http_client not found: ", transport.Tag)
		}
	}
	// Detours belong to the prospective runtime. Bootstrap explicitly uses
	// the current system connection instead, including for shared clients.
	transport.Detour = ""
	// The native decoder materializes the default HTTP/2-with-fallback
	// version. NewHTTPClient already implements that same default.
	if transport.Version == 2 {
		transport.Version = 0
	}
	if !transport.IsEmpty() {
		return E.New("bootstrap over the current system network does not support custom http_client options; provide a valid initial_path")
	}
	return checkRuleSetBootstrapCertificates(options.Certificate, url)
}

func checkRuleSetBootstrapCertificates(certificates *option.CertificateOptions, url string) error {
	if certificates != nil && strings.HasPrefix(strings.ToLower(url), "https:") {
		if certificates.Store != C.CertificateStoreSystem || len(certificates.Certificate) > 0 || len(certificates.CertificatePath) > 0 || len(certificates.CertificateDirectoryPath) > 0 {
			return E.New("bootstrap over the current system network does not support custom certificate options; provide a valid initial_path")
		}
	}
	return nil
}
