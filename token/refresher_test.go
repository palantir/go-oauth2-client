// Copyright (c) 2019 Palantir Technologies. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package token_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/palantir/go-oauth2-client/v3/token"
	"github.com/palantir/pkg/retry"
	werror "github.com/palantir/witchcraft-go-error"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefresher_Run(t *testing.T) {
	provideToken := func(_ context.Context) (string, error) {
		return "foo", nil
	}

	refresher := token.NewRefresher(provideToken, time.Second)
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond*5)
	defer cancel()
	_, err := refresher.Token(timeoutCtx)
	require.Error(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() {
		refresher.Run(ctx)
	})

	wg.Go(func() {
		assert.NoError(t, retry.Do(ctx, func() error {
			token, err := refresher.Token(context.Background())
			if token != "foo" {
				return werror.Error("expected token to be 'foo'")
			}
			if err != nil {
				return werror.Error("expected err to be nil")
			}
			return nil
		}, retry.WithMaxBackoff(10*time.Millisecond), retry.WithMaxAttempts(3)))
		cancel()
	})

	// Wait for refresher to stop after verifying refreshed token.
	wg.Wait()
}

// Note, this test asssumes a certain accuracy of time.Sleep that can't actually be guaranteed, while it's unlikely to
// fail it does add a bit of fragility in order to preserve readability
func TestRefresher_RunFailsAfterSucceeding(t *testing.T) {
	shouldFail := false
	hasFailed := false
	provideToken := func(_ context.Context) (string, error) {
		if shouldFail {
			hasFailed = true
			return "badtoken", werror.Error("failure")
		} else {
			return "goodtoken", nil
		}
	}
	ttl := time.Millisecond * 20
	refresher := token.NewRefresher(provideToken, ttl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() {
		refresher.Run(ctx)
	})

	// Sleep up until before the refresh attempt, which occurs at 1/2 * ttl
	time.Sleep(ttl / 4)
	token, err := refresher.Token(context.Background())
	assert.Equal(t, "goodtoken", token)
	assert.NoError(t, err)

	shouldFail = true

	// Sleep past attempted refresh, which occurs at 1/2 * ttl, after this sleep we are at 3/4 * ttl, so the token is still valid even though a failure has occurred
	time.Sleep(ttl / 2)
	token, err = refresher.Token(context.Background())
	assert.Equal(t, "goodtoken", token)
	assert.NoError(t, err)
	assert.True(t, hasFailed)

	// Sleep past ttl
	time.Sleep(ttl / 2)
	token, err = refresher.Token(context.Background())
	assert.Equal(t, "", token)
	assert.Error(t, err)

	cancel()
	wg.Wait()
}

// Note, this test assumes a certain accuracy of time.Sleep that can't actually be guaranteed, while it's unlikely to
// fail it does add a bit of fragility in order to preserve readability
func TestRefresher_RunSucceedsAfterFailing(t *testing.T) {
	shouldFail := true
	hasFailed := false
	provideToken := func(_ context.Context) (string, error) {
		if shouldFail {
			hasFailed = true
			return "badtoken", werror.Error("failure")
		} else {
			return "goodtoken", nil
		}
	}
	ttl := time.Millisecond * 20
	refresher := token.NewRefresher(provideToken, ttl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() {
		refresher.Run(ctx)
	})

	// Stop failing after a delay so the retry loop can succeed
	wg.Go(func() {
		time.Sleep(ttl / 4)
		shouldFail = false
	})

	// Token() blocks until the first successful acquisition
	tok, err := refresher.Token(context.Background())
	assert.Equal(t, "goodtoken", tok)
	assert.NoError(t, err)
	assert.True(t, hasFailed)

	cancel()
	wg.Wait()
}

func TestRefresher_WaitsForFirstCallToSlowProvider(t *testing.T) {
	blockingChan := make(chan struct{})
	provideToken := func(_ context.Context) (string, error) {
		select {
		case <-blockingChan:
		}
		return "foo", nil
	}

	refresher := token.NewRefresher(provideToken, time.Second)
	go refresher.Run(context.Background())
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
	defer cancel()
	_, err := refresher.Token(timeoutCtx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out waiting for initial token acquisition")
	close(blockingChan)
	token, err := refresher.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "foo", token)
}

func TestRefresher_ErrorsOnProviderError(t *testing.T) {
	provideToken := func(_ context.Context) (string, error) {
		return "", werror.Error("underlying provider failure")
	}

	refresher := token.NewRefresher(provideToken, time.Second)
	go refresher.Run(context.Background())
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := refresher.Token(timeoutCtx)
	require.Error(t, err)
	// Error surfaces both the init-timeout and the underlying cause.
	require.Contains(t, err.Error(), "timed out waiting for initial token acquisition")
	require.Contains(t, err.Error(), "underlying provider failure")
}

func TestRefresher_InitTimeoutBoundsBackgroundContext(t *testing.T) {
	provideToken := func(_ context.Context) (string, error) {
		return "", werror.Error("always fails")
	}

	refresher := token.NewRefresher(provideToken, time.Second, token.WithInitTimeout(50*time.Millisecond))
	go refresher.Run(context.Background())

	start := time.Now()
	_, err := refresher.Token(context.Background())
	elapsed := time.Since(start)

	require.Error(t, err)
	require.Contains(t, err.Error(), "timed out waiting for initial token acquisition")
	require.Contains(t, err.Error(), "always fails")
	// Should return near the init timeout and not block forever
	assert.Less(t, elapsed, 500*time.Millisecond)
}

func TestRefresher_RetriesBeforeUnblocking(t *testing.T) {
	var attempts atomic.Int64
	provideToken := func(_ context.Context) (string, error) {
		if attempts.Add(1) <= 3 {
			return "", werror.Error("transient failure")
		}
		return "goodtoken", nil
	}

	refresher := token.NewRefresher(provideToken, time.Second)
	go refresher.Run(context.Background())

	// Token() should block through failures and return once a retry succeeds
	tok, err := refresher.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "goodtoken", tok)
	assert.Greater(t, attempts.Load(), int64(3))
}
