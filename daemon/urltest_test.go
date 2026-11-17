package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type probeOutbound struct {
	outbound.Adapter
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (o *probeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx, network, destination)
}

func (o *probeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type urlTestFixture struct {
	ctx            context.Context
	service        *StartedService
	client         StartedServiceClient
	connection     *grpc.ClientConn
	cancelInstance context.CancelFunc
	nodes          map[string]*probeOutbound
	selector       *group.Selector
}

func newURLTestFixture(t *testing.T) *urlTestFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	factory := log.NewNOPFactory()
	history := urltest.NewHistoryStorage()
	t.Cleanup(func() { require.NoError(t, history.Close()) })
	registry := outbound.NewRegistry()
	nodes := make(map[string]*probeOutbound)
	outbound.Register(registry, "probe", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
		node := &probeOutbound{
			Adapter: outbound.NewAdapter("probe", tag, []string{N.NetworkTCP}, nil),
			dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
				return nil, errors.New("unconfigured probe")
			},
		}
		nodes[tag] = node
		return node, nil
	})
	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)
	endpoints := endpoint.NewManager(nil)
	manager := outbound.NewManager(registry, endpoints, "selector")
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	ctx = service.ContextWithPtr(ctx, history)
	instanceCtx, cancelInstance := context.WithCancel(ctx)
	t.Cleanup(cancelInstance)
	for _, tag := range []string{"chosen", "other"} {
		require.NoError(t, manager.Create(ctx, nil, factory.Logger(), tag, "probe", nil))
	}
	require.NoError(t, manager.Create(ctx, nil, factory.Logger(), "selector", "selector", &option.SelectorOutboundOptions{
		Outbounds: []string{"chosen", "other"}, Default: "chosen",
	}))
	selected, loaded := manager.Outbound("selector")
	require.True(t, loaded)
	selector := selected.(*group.Selector)
	scope := adapter.NewScope(ctx, factory.Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start("selector", selector, adapter.StartStateStart))

	updates := observable.NewSubscriber[struct{}](1)
	updateObserver := observable.NewObserver(updates, 1)
	t.Cleanup(func() { require.NoError(t, updateObserver.Close()) })
	statuses := observable.NewSubscriber[*ServiceStatus](1)
	statusObserver := observable.NewObserver(statuses, 1)
	t.Cleanup(func() { require.NoError(t, statusObserver.Close()) })
	history.AddUpdateHook(updates)
	started := &StartedService{
		ctx: ctx, serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		urlTestSubscriber: updates, urlTestObserver: updateObserver,
		serviceStatusSubscriber: statuses, serviceStatusObserver: statusObserver,
		instance: &Instance{
			ctx: instanceCtx, outboundManager: manager, endpointManager: endpoints,
			urlTestHistoryStorage: history, logFactory: factory,
		},
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterStartedServiceServer(server, started)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		cancel()
		server.Stop()
		require.NoError(t, <-serveDone)
	})
	connection, err := grpc.NewClient("passthrough:///urltest",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	return &urlTestFixture{
		ctx: ctx, service: started, client: NewStartedServiceClient(connection),
		connection: connection, cancelInstance: cancelInstance, nodes: nodes, selector: selector,
	}
}

func (f *urlTestFixture) addGroup(t *testing.T, tag, kind string, options any) adapter.OutboundGroup {
	t.Helper()
	instance := f.service.instance
	require.NoError(t, instance.outboundManager.Create(instance.ctx, nil, instance.logFactory.Logger(), tag, kind, options))
	detour, loaded := instance.outboundManager.Outbound(tag)
	require.True(t, loaded)
	scope := adapter.NewScope(instance.ctx, instance.logFactory.Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start(tag, detour.(adapter.Lifecycle), adapter.StartStateStart))
	return detour.(adapter.OutboundGroup)
}

type urlTestResponse struct {
	list *OutboundList
	err  error
}

func (f *urlTestFixture) testAsync(ctx context.Context, tag string) <-chan urlTestResponse {
	done := make(chan urlTestResponse, 1)
	go func() {
		list, err := f.client.URLTest(ctx, &URLTestRequest{OutboundTag: tag})
		done <- urlTestResponse{list, err}
	}()
	return done
}

func requireURLTestBlocked(t *testing.T, done <-chan urlTestResponse) {
	t.Helper()
	select {
	case response := <-done:
		t.Fatalf("URLTest returned before the blocked probe completed: %v", response.err)
	case <-time.After(50 * time.Millisecond):
	}
}

func resultItems(t *testing.T, list *OutboundList) map[string]*GroupItem {
	t.Helper()
	require.NotNil(t, list)
	results := make(map[string]*GroupItem)
	for _, item := range list.Outbounds {
		require.NotContains(t, results, item.Tag, "duplicate outbound tag")
		require.NotNil(t, item.UrlTestResult, item.Tag)
		results[item.Tag] = item
	}
	return results
}

func TestURLTestResultSubscriptions(t *testing.T) {
	fixture := newURLTestFixture(t)
	groups, err := fixture.client.SubscribeGroups(fixture.ctx, &emptypb.Empty{})
	require.NoError(t, err)
	initialGroups, err := groups.Recv()
	require.NoError(t, err)
	require.Len(t, initialGroups.Group, 1)
	require.True(t, initialGroups.Group[0].Selectable)
	require.Nil(t, initialGroups.Group[0].Items[0].UrlTestResult)
	outbounds, err := fixture.client.SubscribeOutbounds(fixture.ctx, &emptypb.Empty{})
	require.NoError(t, err)
	initialOutbounds, err := outbounds.Recv()
	require.NoError(t, err)
	require.Nil(t, initialOutbounds.Outbounds[0].UrlTestResult)

	for _, step := range []struct {
		name       string
		delay      uint16
		err        error
		success    bool
		history    bool
		invalidate bool
		errorText  string
	}{
		{name: "failure", err: errors.New("connection refused"), errorText: "connection refused"},
		{name: "failure to zero success", success: true, history: true},
		{name: "success to empty error failure", err: errors.New("")},
		{name: "maximum delay success", delay: 65535, success: true, history: true},
		{name: "connection failure invalidates only history", delay: 65535, success: true, invalidate: true},
	} {
		t.Run(step.name, func(t *testing.T) {
			storage := fixture.service.instance.urlTestHistoryStorage
			if step.invalidate {
				storage.DeleteURLTestHistory("chosen")
			} else {
				storage.StoreURLTestResult("chosen", step.delay, step.err)
			}
			groupSnapshot, err := groups.Recv()
			require.NoError(t, err)
			outboundSnapshot, err := outbounds.Recv()
			require.NoError(t, err)
			item := groupSnapshot.Group[0].Items[0]
			require.Equal(t, "chosen", item.Tag)
			require.NotNil(t, item.UrlTestResult)
			require.Equal(t, step.success, item.UrlTestResult.Success)
			require.Equal(t, int32(step.delay), item.UrlTestResult.Delay)
			require.Equal(t, step.errorText, item.UrlTestResult.Error)
			require.Equal(t, storage.LoadURLTestResult("chosen").Time.Unix(), item.UrlTestResult.Time)
			if step.history {
				require.Equal(t, item.UrlTestResult.Time, item.UrlTestTime)
				require.Equal(t, int32(step.delay), item.UrlTestDelay)
			} else {
				require.Zero(t, item.UrlTestTime)
				require.Zero(t, item.UrlTestDelay)
			}
			require.True(t, proto.Equal(item.UrlTestResult, outboundSnapshot.Outbounds[0].UrlTestResult))
			require.True(t, proto.Equal(item.UrlTestResult, outboundSnapshot.Outbounds[2].UrlTestResult))
			require.Nil(t, groupSnapshot.Group[0].Items[1].UrlTestResult)
			require.Equal(t, "chosen", groupSnapshot.Group[0].Selected)
			require.Equal(t, "chosen", fixture.selector.Selected(N.NetworkTCP).Tag())
		})
	}
}

func TestURLTestWaitsForProbeCompletion(t *testing.T) {
	fixture := newURLTestFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.nodes["chosen"].dial = func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		close(entered)
		select {
		case <-release:
			return nil, errors.New("probe dial failed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	storage := fixture.service.instance.urlTestHistoryStorage
	storage.StoreURLTestResult("chosen", 123, nil)
	previous := storage.LoadURLTestResult("chosen")
	completed := fixture.testAsync(fixture.ctx, "chosen")
	select {
	case <-entered:
	case <-fixture.ctx.Done():
		t.Fatal(fixture.ctx.Err())
	}
	requireURLTestBlocked(t, completed)
	require.Same(t, previous, storage.LoadURLTestResult("chosen"))
	close(release)
	response := <-completed
	require.NoError(t, response.err)
	items := resultItems(t, response.list)
	require.Len(t, items, 1)
	require.False(t, items["chosen"].UrlTestResult.Success)
	require.Equal(t, "probe dial failed", items["chosen"].UrlTestResult.Error)
	require.Zero(t, items["chosen"].UrlTestTime)
	require.Zero(t, items["chosen"].UrlTestDelay)
	result := storage.LoadURLTestResult("chosen")
	require.NotSame(t, previous, result)
	require.EqualError(t, result.Error, "probe dial failed")
	require.Equal(t, result.Time.Unix(), items["chosen"].UrlTestResult.Time)
}

func TestURLTestBatchRecordsTransitionsWithoutSelecting(t *testing.T) {
	fixture := newURLTestFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	var failing atomic.Bool
	probeError := errors.New("probe dial failed")
	for tag, node := range fixture.nodes {
		node.dial = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			if tag == "chosen" && failing.Load() {
				return nil, probeError
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, destination.String())
		}
	}
	storage := fixture.service.instance.urlTestHistoryStorage
	for _, fail := range []bool{true, false, true} {
		failing.Store(fail)
		delays := group.URLTestOutbounds(fixture.ctx, fixture.service.instance.outboundManager, storage,
			log.NewNOPFactory().Logger(), []adapter.Outbound{fixture.selector}, server.URL, 0, true)
		result := storage.LoadURLTestResult("chosen")
		require.NotNil(t, result)
		if fail {
			require.ErrorIs(t, result.Error, probeError)
			require.NotContains(t, delays, "chosen")
			require.Nil(t, storage.LoadURLTestHistory("chosen"))
		} else {
			require.NoError(t, result.Error)
			require.Contains(t, delays, "chosen")
			require.Equal(t, delays["chosen"], result.Delay)
			require.NotNil(t, storage.LoadURLTestHistory("chosen"))
		}
		require.Contains(t, delays, "other")
		require.NoError(t, storage.LoadURLTestResult("other").Error)
		require.Equal(t, "chosen", fixture.selector.Selected(N.NetworkTCP).Tag())
	}
}

func TestURLTestLegacyEmptyResponse(t *testing.T) {
	fixture := newURLTestFixture(t)
	fixture.nodes["chosen"].dial = func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return nil, errors.New("")
	}
	// Exercise an old client's actual response decoder on the same RPC.
	var response emptypb.Empty
	require.NoError(t, fixture.connection.Invoke(fixture.ctx, StartedService_URLTest_FullMethodName,
		&URLTestRequest{OutboundTag: "chosen"}, &response))
	wire, err := proto.Marshal(&response)
	require.NoError(t, err)
	var list OutboundList
	require.NoError(t, proto.Unmarshal(wire, &list))
	items := resultItems(t, &list)
	require.Len(t, items, 1)
	require.False(t, items["chosen"].UrlTestResult.Success)
	require.Empty(t, items["chosen"].UrlTestResult.Error)
	require.Positive(t, items["chosen"].UrlTestResult.Time)
}

func TestURLTestCancellation(t *testing.T) {
	for _, tag := range []string{"chosen", "selector", "automatic"} {
		for _, cancelService := range []bool{false, true} {
			name := tag + "/request"
			if cancelService {
				name = tag + "/service"
			}
			t.Run(name, func(t *testing.T) {
				fixture := newURLTestFixture(t)
				fixture.addGroup(t, "automatic", "urltest", &option.URLTestOutboundOptions{
					Outbounds: []string{"chosen", "other"},
				})
				entered := make(chan struct{})
				exited := make(chan struct{})
				fixture.nodes["chosen"].dial = func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
					close(entered)
					<-ctx.Done()
					close(exited)
					return nil, ctx.Err()
				}
				storage := fixture.service.instance.urlTestHistoryStorage
				previous := storage.StoreURLTestResult("chosen", 123, nil)
				ctx, cancel := context.WithCancel(fixture.ctx)
				defer cancel()
				completed := fixture.testAsync(ctx, tag)
				select {
				case <-entered:
				case <-fixture.ctx.Done():
					t.Fatal(fixture.ctx.Err())
				}
				if cancelService {
					fixture.cancelInstance()
				} else {
					cancel()
				}
				response := <-completed
				require.Nil(t, response.list)
				require.Equal(t, codes.Canceled, status.Code(response.err))
				select {
				case <-exited:
				case <-fixture.ctx.Done():
					t.Fatal(fixture.ctx.Err())
				}
				require.Same(t, previous, storage.LoadURLTestResult("chosen"))
			})
		}
	}
}

func TestURLTestConcurrentGroupWaitsForSharedProbe(t *testing.T) {
	fixture := newURLTestFixture(t)
	fixture.addGroup(t, "automatic", "urltest", &option.URLTestOutboundOptions{
		Outbounds: []string{"chosen"},
	})
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	fixture.nodes["chosen"].dial = func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return nil, errors.New("shared probe failure")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	first := fixture.testAsync(fixture.ctx, "automatic")
	select {
	case <-entered:
	case <-fixture.ctx.Done():
		t.Fatal(fixture.ctx.Err())
	}
	second := fixture.testAsync(fixture.ctx, "automatic")
	cancelCtx, cancel := context.WithCancel(fixture.ctx)
	cancelledWaiter := fixture.testAsync(cancelCtx, "automatic")
	requireURLTestBlocked(t, first)
	requireURLTestBlocked(t, second)
	requireURLTestBlocked(t, cancelledWaiter)
	cancel()
	require.Equal(t, codes.Canceled, status.Code((<-cancelledWaiter).err))
	require.Equal(t, int32(1), calls.Load())
	close(release)
	firstResponse := <-first
	secondResponse := <-second
	require.NoError(t, firstResponse.err)
	require.NoError(t, secondResponse.err)
	firstItems := resultItems(t, firstResponse.list)
	secondItems := resultItems(t, secondResponse.list)
	require.Equal(t, firstItems, secondItems)
	require.Len(t, firstItems, 2)
	require.False(t, firstItems["chosen"].UrlTestResult.Success)
	require.Equal(t, "shared probe failure", firstItems["chosen"].UrlTestResult.Error)
	require.Equal(t, int32(1), calls.Load())
}

func TestURLTestManualWaitsForIntervalThenForcesAllNodes(t *testing.T) {
	fixture := newURLTestFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	entered := make(chan struct{})
	release := make(chan struct{})
	var chosenCalls, otherCalls atomic.Int32
	for tag, node := range fixture.nodes {
		node.dial = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			if tag == "chosen" {
				chosenCalls.Add(1)
			} else if otherCalls.Add(1) == 1 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, destination.String())
		}
	}
	instance := fixture.service.instance
	instance.urlTestHistoryStorage.StoreURLTestResult("chosen", 123, nil)
	checker, err := group.NewURLTestGroup(instance.ctx, instance.outboundManager, instance.logFactory.Logger(),
		[]adapter.Outbound{fixture.nodes["chosen"], fixture.nodes["other"]}, server.URL, time.Minute, 0, 0, false)
	require.NoError(t, err)
	intervalDone := make(chan struct{})
	go func() {
		checker.CheckOutbounds(fixture.ctx, false)
		close(intervalDone)
	}()
	select {
	case <-entered:
	case <-fixture.ctx.Done():
		t.Fatal(fixture.ctx.Err())
	}
	manualDone := make(chan struct{})
	var delays map[string]uint16
	var manualErr error
	go func() {
		delays, manualErr = checker.URLTest(fixture.ctx)
		close(manualDone)
	}()
	select {
	case <-manualDone:
		t.Fatal("manual URLTest completed while the interval probe was blocked")
	case <-time.After(50 * time.Millisecond):
	}
	require.Zero(t, chosenCalls.Load())
	close(release)
	<-intervalDone
	<-manualDone
	require.NoError(t, manualErr)
	require.Len(t, delays, 2)
	require.Equal(t, int32(1), chosenCalls.Load())
	require.Equal(t, int32(2), otherCalls.Load())
}

func TestURLTestNestedGroupsReturnCurrentResults(t *testing.T) {
	fixture := newURLTestFixture(t)
	requests := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r
		// The existing probe defines HTTP completion, not status 204, as success.
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	var chosenCalls, otherCalls atomic.Int32
	fixture.nodes["chosen"].dial = func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		chosenCalls.Add(1)
		return nil, errors.New("")
	}
	fixture.nodes["other"].dial = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		otherCalls.Add(1)
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, destination.String())
	}
	automatic := fixture.addGroup(t, "automatic", "urltest", &option.URLTestOutboundOptions{
		Outbounds: []string{"chosen", "other"}, URL: server.URL + "/nested",
	})
	inner := fixture.addGroup(t, "inner", "selector", &option.SelectorOutboundOptions{
		Outbounds: []string{"chosen", "automatic"}, Default: "chosen",
	})
	outer := fixture.addGroup(t, "outer", "selector", &option.SelectorOutboundOptions{
		Outbounds: []string{"inner", "chosen", "automatic"}, Default: "inner",
	})
	require.Equal(t, "chosen", automatic.Selected(N.NetworkTCP).Tag())
	storage := fixture.service.instance.urlTestHistoryStorage
	oldChosen := storage.StoreURLTestResult("chosen", 321, nil)
	oldOther := storage.StoreURLTestResult("other", 0, errors.New("old failure"))
	list, err := fixture.client.URLTest(fixture.ctx, &URLTestRequest{OutboundTag: "outer"})
	require.NoError(t, err)
	items := resultItems(t, list)
	require.Len(t, items, 5)
	require.Equal(t, int32(2), chosenCalls.Load(), "ordinary nesting deduplicates; URL-test groups retain their own URL probes")
	require.Equal(t, int32(1), otherCalls.Load())
	require.False(t, items["chosen"].UrlTestResult.Success)
	require.Empty(t, items["chosen"].UrlTestResult.Error)
	require.True(t, items["other"].UrlTestResult.Success)
	require.Equal(t, items["chosen"].UrlTestResult, items["inner"].UrlTestResult)
	require.Equal(t, items["chosen"].UrlTestResult, items["outer"].UrlTestResult)
	require.Equal(t, items["other"].UrlTestResult, items["automatic"].UrlTestResult)
	require.NotSame(t, oldChosen, storage.LoadURLTestResult("chosen"))
	require.NotSame(t, oldOther, storage.LoadURLTestResult("other"))
	require.Equal(t, "chosen", inner.Selected(N.NetworkTCP).Tag())
	require.Equal(t, "inner", outer.Selected(N.NetworkTCP).Tag())
	require.Equal(t, "other", automatic.Selected(N.NetworkTCP).Tag(), "automatic update check is preserved")
	select {
	case request := <-requests:
		require.Equal(t, http.MethodHead, request.Method)
		require.Equal(t, "/nested", request.URL.Path)
	default:
		t.Fatal("nested URL-test group did not probe its own URL")
	}
}

func TestURLTestBatchKeepsItsOwnCompletedResults(t *testing.T) {
	fixture := newURLTestFixture(t)
	var chosenCalls atomic.Int32
	fixture.nodes["chosen"].dial = func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		if chosenCalls.Add(1) == 1 {
			return nil, errors.New("batch failure")
		}
		return nil, errors.New("later single failure")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.nodes["other"].dial = func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		close(entered)
		select {
		case <-release:
			return nil, errors.New("other failure")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	groups, err := fixture.client.SubscribeGroups(fixture.ctx, &emptypb.Empty{})
	require.NoError(t, err)
	_, err = groups.Recv()
	require.NoError(t, err)
	batch := fixture.testAsync(fixture.ctx, "selector")
	select {
	case <-entered:
	case <-fixture.ctx.Done():
		t.Fatal(fixture.ctx.Err())
	}
	update, err := groups.Recv()
	require.NoError(t, err)
	require.Equal(t, "batch failure", update.Group[0].Items[0].UrlTestResult.Error)
	later, err := fixture.client.URLTest(fixture.ctx, &URLTestRequest{OutboundTag: "chosen"})
	require.NoError(t, err)
	require.Equal(t, "later single failure", resultItems(t, later)["chosen"].UrlTestResult.Error)
	close(release)
	response := <-batch
	require.NoError(t, response.err)
	items := resultItems(t, response.list)
	require.Len(t, items, 3)
	require.Equal(t, "batch failure", items["chosen"].UrlTestResult.Error)
	require.Equal(t, items["chosen"].UrlTestResult, items["selector"].UrlTestResult)
	require.Equal(t, "later single failure", fixture.service.instance.urlTestHistoryStorage.LoadURLTestResult("chosen").Error.Error())
	require.Equal(t, "chosen", fixture.selector.Selected(N.NetworkTCP).Tag())
}
