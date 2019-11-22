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
	"testing"
	"time"

	"github.com/palantir/go-oauth2-client/token"
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		refresher.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
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
	}()

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
	wg.Add(1)
	go func() {
		defer wg.Done()
		refresher.Run(ctx)
	}()

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

// Note, this test asssumes a certain accuracy of time.Sleep that can't actually be guaranteed, while it's unlikely to
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		refresher.Run(ctx)
	}()

	// Sleep to allow at least one failed token attempt
	time.Sleep(ttl / 4)
	token, err := refresher.Token(context.Background())
	assert.Equal(t, "", token)
	assert.Error(t, err)
	assert.True(t, hasFailed)

	shouldFail = false

	assert.NoError(t, retry.Do(ctx, func() error {
		token, err := refresher.Token(context.Background())
		if token != "goodtoken" {
			return werror.Error("expected token to be 'goodtoken'")
		}
		if err != nil {
			return werror.Error("expected err to be nil")
		}
		return nil
	}, retry.WithMaxBackoff(10*time.Millisecond), retry.WithMaxAttempts(10)))

	token, err = refresher.Token(context.Background())
	assert.Equal(t, "goodtoken", token)
	assert.NoError(t, err)

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
	assert.Contains(t, err.Error(), "context completed")
	close(blockingChan)
	token, err := refresher.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "foo", token)
}

func TestRefresher_ErrorsOnProviderError(t *testing.T) {
	provideToken := func(_ context.Context) (string, error) {
		return "", werror.Error("foo")
	}

	refresher := token.NewRefresher(provideToken, time.Second)
	go refresher.Run(context.Background())
	_, err := refresher.Token(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "foo")
}
