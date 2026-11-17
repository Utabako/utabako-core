package libbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPrepareRuleSetsWithoutHardLinks(t *testing.T) {
	if os.Getenv("LIBBOX_RULE_SET_DENY_LINK_TEST") == "1" {
		// Restrict only this test subprocess. TSYNC also covers the Go runtime's
		// other threads, so preparation cannot evade the denied linkat syscall
		// by resuming its goroutine on another thread.
		runtime.LockOSThread()
		require.NoError(t, unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		filter := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_LINKAT, Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		}
		program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
		runtime.KeepAlive(filter)
		runtime.UnlockOSThread()
		require.Zero(t, errno)
		require.Zero(t, result, "seccomp thread synchronization must succeed")
		directory := t.TempDir()
		source := filepath.Join(directory, "source")
		require.NoError(t, os.WriteFile(source, []byte("probe"), 0o600))
		require.ErrorIs(t, os.Link(source, filepath.Join(directory, "link")), unix.EPERM)
		// Exercise actual SDK downloads, immutable publication, reuse and
		// conflicting existing content with hard links demonstrably forbidden.
		t.Run("concurrent publication", TestPrepareRuleSetsConcurrentImmutableSeeds)
		return
	}
	executable, err := os.Executable()
	require.NoError(t, err)
	command := exec.Command(executable, "-test.run=^TestPrepareRuleSetsWithoutHardLinks$", "-test.count=1")
	command.Env = append(os.Environ(), "LIBBOX_RULE_SET_DENY_LINK_TEST=1")
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
}
