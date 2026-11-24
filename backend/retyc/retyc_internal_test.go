package retyc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rclone/rclone/fs/fserrors"
	"github.com/retyc/retyc-cli/core/api"
	"github.com/retyc/retyc-cli/core/vfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplit(t *testing.T) {
	for _, test := range []struct {
		root, remote     string
		space, spacePath string
	}{
		{"", "", "", "/"},
		{"", "space", "space", "/"},
		{"", "space/dir/file", "space", "/dir/file"},
		{"space", "", "space", "/"},
		{"space", "file", "space", "/file"},
		{"space/dir", "sub/file", "space", "/dir/sub/file"},
		{"", "spa／ce/a／b", "spa／ce", "/a／b"},
		{"space", "．", "space", "/．"},
	} {
		f := &Fs{root: test.root, opt: Options{Enc: defaultEncoding}}
		space, spacePath := f.split(test.remote)
		assert.Equal(t, test.space, space, "root %q remote %q", test.root, test.remote)
		assert.Equal(t, test.spacePath, spacePath, "root %q remote %q", test.root, test.remote)
	}
}

func TestLoginState(t *testing.T) {
	want := loginState{
		interval:   7 * time.Second,
		expiry:     time.Unix(1700000000, 0),
		deviceCode: "code,with,commas",
	}
	got, err := parseLoginState(want.String())
	require.NoError(t, err)
	assert.Equal(t, want.interval, got.interval)
	assert.True(t, want.expiry.Equal(got.expiry))
	assert.Equal(t, want.deviceCode, got.deviceCode)

	got, err = parseLoginState(loginState{expiry: want.expiry, deviceCode: "x"}.String())
	require.NoError(t, err)
	assert.Equal(t, defaultPollInterval, got.interval)

	for _, state := range []string{
		pollState,
		pollState + "5,1700000000",
		pollState + "5,1700000000,",
		pollState + "x,1700000000,code",
		pollState + "5,x,code",
	} {
		_, err := parseLoginState(state)
		assert.Error(t, err, state)
	}
}

func TestRetryErr(t *testing.T) {
	assert.NoError(t, retryErr(nil))

	for _, status := range []int{500, 502, 503, 599} {
		err := retryErr(fmt.Errorf("upload: %w", &api.HTTPError{Status: status}))
		assert.True(t, fserrors.IsRetryError(err), status)
		assert.False(t, fserrors.IsNoRetryError(err), status)
	}
	for _, status := range []int{400, 404, 409, 429, 600} {
		err := retryErr(fmt.Errorf("upload: %w", &api.HTTPError{Status: status}))
		assert.False(t, fserrors.IsRetryError(err), status)
		assert.False(t, fserrors.IsNoRetryError(err), status)
	}
	for _, kind := range []error{vfs.ErrStorageExceeded, vfs.ErrForbidden, vfs.ErrUnauthenticated} {
		err := retryErr(fmt.Errorf("upload: %w", kind))
		assert.True(t, fserrors.IsNoRetryError(err), kind)
		assert.False(t, fserrors.IsRetryError(err), kind)
		assert.ErrorIs(t, err, kind)
	}
	plain := errors.New("plain")
	assert.Equal(t, plain, retryErr(plain))
}

// newTestVFS returns a vfs.FS which makes no request, counting the calls
func newTestVFS(calls *atomic.Int32) func() (*vfs.FS, error) {
	return func() (*vfs.FS, error) {
		calls.Add(1)
		return vfs.New(nil, vfs.Options{}), nil
	}
}

// users returns the users of the connection held for key, -1 for none
func users(key connKey) int {
	connsMu.Lock()
	defer connsMu.Unlock()
	if c := conns[key]; c != nil {
		return c.users
	}
	return -1
}

func TestConnShared(t *testing.T) {
	ctx := context.Background()
	key := connKey{name: t.Name(), url: "https://example.com", passphrase: "secret"}
	var calls atomic.Int32

	c1, err := getConn(ctx, key, newTestVFS(&calls))
	require.NoError(t, err)
	c2, err := getConn(ctx, key, newTestVFS(&calls))
	require.NoError(t, err)
	assert.Same(t, c1, c2)
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, 2, users(key))

	// Any other setting is another connection
	for _, other := range []connKey{
		{name: key.name + "2", url: key.url, passphrase: key.passphrase},
		{name: key.name, url: key.url + "/2", passphrase: key.passphrase},
		{name: key.name, url: key.url, passphrase: key.passphrase + "2"},
	} {
		c, err := getConn(ctx, other, newTestVFS(&calls))
		require.NoError(t, err)
		assert.NotSame(t, c1, c)
		require.NoError(t, c.release())
		assert.Equal(t, -1, users(other))
	}

	require.NoError(t, c1.release())
	assert.Equal(t, 1, users(key))
	require.NoError(t, c2.release())
	assert.Equal(t, -1, users(key))

	// Once released by all, the next user makes a new connection
	c3, err := getConn(ctx, key, newTestVFS(&calls))
	require.NoError(t, err)
	assert.NotSame(t, c1, c3)
	assert.Equal(t, int32(5), calls.Load())
	require.NoError(t, c3.release())
}

func TestConnConcurrent(t *testing.T) {
	ctx := context.Background()
	key := connKey{name: t.Name()}
	var calls atomic.Int32
	start := make(chan struct{})
	slow := func() (*vfs.FS, error) {
		<-start
		return newTestVFS(&calls)()
	}

	const n = 10
	got := make([]*conn, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			c, err := getConn(ctx, key, slow)
			assert.NoError(t, err)
			got[i] = c
		})
	}
	// Let the callers queue up behind the first before it finishes
	time.Sleep(50 * time.Millisecond)
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, n, users(key))
	for _, c := range got {
		assert.Same(t, got[0], c)
		require.NoError(t, c.release())
	}
	assert.Equal(t, -1, users(key))
}

func TestConnError(t *testing.T) {
	ctx := context.Background()
	key := connKey{name: t.Name()}
	errBuild := errors.New("wrong passphrase")
	start := make(chan struct{})
	failing := func() (*vfs.FS, error) {
		<-start
		return nil, errBuild
	}

	const n = 5
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			c, err := getConn(ctx, key, failing)
			assert.Nil(t, c)
			assert.ErrorIs(t, err, errBuild)
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(start)
	wg.Wait()
	assert.Equal(t, -1, users(key))

	// A failure leaves nothing behind
	var calls atomic.Int32
	c, err := getConn(ctx, key, newTestVFS(&calls))
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load())
	require.NoError(t, c.release())
}

func TestConnWaitCancelled(t *testing.T) {
	key := connKey{name: t.Name()}
	start := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		c, err := getConn(context.Background(), key, func() (*vfs.FS, error) {
			<-start
			return newTestVFS(&calls)()
		})
		assert.NoError(t, err)
		assert.NoError(t, c.release())
	}()
	require.Eventually(t, func() bool { return users(key) == 0 }, time.Second, time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, err := getConn(ctx, key, newTestVFS(&calls))
	assert.Nil(t, c)
	assert.ErrorIs(t, err, context.Canceled)

	close(start)
	<-done
	assert.Equal(t, -1, users(key))
}

func TestShutdownTwice(t *testing.T) {
	ctx := context.Background()
	key := connKey{name: t.Name()}
	var calls atomic.Int32
	newFs := func() *Fs {
		c, err := getConn(ctx, key, newTestVFS(&calls))
		require.NoError(t, err)
		return &Fs{conn: c, vfs: c.vfs}
	}
	f1, f2 := newFs(), newFs()
	assert.Same(t, f1.vfs, f2.vfs)

	require.NoError(t, f1.Shutdown(ctx))
	require.NoError(t, f1.Shutdown(ctx))
	assert.Equal(t, 1, users(key), "a second Shutdown must not count again")

	require.NoError(t, f2.Shutdown(ctx))
	assert.Equal(t, -1, users(key))
	assert.Equal(t, int32(1), calls.Load())
}
