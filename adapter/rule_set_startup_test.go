package adapter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuleSetStartupReportsWaitingUntilLastDialResumes(t *testing.T) {
	var startup RuleSetStartup
	require.Empty(t, startup.Stage())
	finishLoading := startup.BeginLoading()
	require.Equal(t, "loading-rule-sets", startup.Stage())
	resumeFirst := startup.BeginZeroTierWait()
	resumeSecond := startup.BeginZeroTierWait()
	require.Equal(t, "waiting-zerotier-authorization", startup.Stage())
	resumeFirst()
	require.Equal(t, "waiting-zerotier-authorization", startup.Stage())
	resumeSecond()
	require.Equal(t, "loading-rule-sets", startup.Stage())
	finishLoading()
	require.Empty(t, startup.Stage())
}
