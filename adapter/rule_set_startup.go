package adapter

import (
	"context"
	"sync"
)

// RuleSetStartup reports router startup progress. Its zero value is idle.
type RuleSetStartup struct {
	mu              sync.Mutex
	loading         bool
	waitingZeroTier int
}

func (s *RuleSetStartup) Stage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loading {
		return ""
	}
	if s.waitingZeroTier > 0 {
		return "waiting-zerotier-authorization"
	}
	return "loading-rule-sets"
}

func (s *RuleSetStartup) BeginLoading() func() {
	s.mu.Lock()
	s.loading = true
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.loading = false
		s.mu.Unlock()
	}
}

func (s *RuleSetStartup) BeginZeroTierWait() func() {
	s.mu.Lock()
	s.waitingZeroTier++
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.waitingZeroTier--
		s.mu.Unlock()
	}
}

type ruleSetStartupRequestKey struct{}

// ContextWithRuleSetStartupRequest preserves the original cold fetch context
// even when the HTTP transport detaches its dial from request cancellation.
func ContextWithRuleSetStartupRequest(ctx context.Context) context.Context {
	return context.WithValue(ctx, ruleSetStartupRequestKey{}, ctx)
}

func RuleSetStartupRequestFromContext(ctx context.Context) context.Context {
	request, _ := ctx.Value(ruleSetStartupRequestKey{}).(context.Context)
	return request
}
