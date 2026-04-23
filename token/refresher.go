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

package token

import (
	"context"
	"sync"
	"time"

	"github.com/palantir/pkg/retry"
	werror "github.com/palantir/witchcraft-go-error"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// defaultInitTimeout is the maximum time Token() will block waiting for the first successful
// token acquisition when the caller's context has no earlier deadline. Callers may override
// this with WithInitTimeout.
const defaultInitTimeout = 60 * time.Second

// Refresher periodically updates its token via its Provider.
// This type provides thread-safe access to an up-to-date token.
type Refresher struct {
	provideToken Provider
	tokenData    tokenData
	// tokenDataInitialized represents whether a token has been successfully acquired by being a closed channel.
	tokenDataInitialized chan struct{}
	tokenTTL             time.Duration
	initTimeout          time.Duration
	tokenDataLock        sync.RWMutex
}

// RefresherOption configures a Refresher at construction time.
type RefresherOption func(*Refresher)

// WithInitTimeout overrides the maximum time Token() will block waiting for the first
// successful token acquisition. Only applies until the first success; subsequent calls to
// Token() return immediately with the currently stored value.
func WithInitTimeout(d time.Duration) RefresherOption {
	return func(r *Refresher) {
		r.initTimeout = d
	}
}

type tokenData struct {
	// token is the last token that was acquired without error
	token string
	// tokenAcquiredTime is the time token was acquired without error or nil if this has never happened
	tokenAcquiredTime time.Time
	// tokenAcquireError represents the error from the most recent token acquire attempt or nil if no attempt has been made
	tokenAcquireError error
}

// NewRefresher constructs a Refresher from a Provider and a token's TTL.
func NewRefresher(provideToken Provider, tokenTTL time.Duration, opts ...RefresherOption) *Refresher {
	r := &Refresher{
		provideToken: provideToken,
		tokenData: tokenData{
			token:             "",
			tokenAcquiredTime: time.Time{},
			tokenAcquireError: werror.Error("token is not yet initialized"),
		},
		tokenDataInitialized: make(chan struct{}),
		tokenTTL:             tokenTTL,
		initTimeout:          defaultInitTimeout,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Token returns the currently stored token or an error if (1) no token has been successfully
// acquired before the initialization timeout elapses or the caller's context is cancelled, or
// (2) the stored token is expired and no newer token has been acquired.
// Prior to the first successful acquisition, this method blocks until either a token is
// acquired, the caller's context is cancelled, or the initialization timeout (see
// WithInitTimeout, default 60s) elapses. Once a token has been acquired, this method returns
// immediately with the currently stored value.
func (r *Refresher) Token(ctx context.Context) (string, error) {
	if err := r.waitForInitialized(ctx); err != nil {
		return "", err
	}
	r.tokenDataLock.RLock()
	defer r.tokenDataLock.RUnlock()

	// possible error cases
	// * the stored token is the empty string
	//     * every attempt to get the token has failed (it is not possible that no attempt has completed, see wait for initialized above)
	// * the stored token is not the empty string
	//     * the stored token is expired
	//         * the last n attempts to get the token have all failed
	//         * there have been no completed attempts since the last success
	errorParam := werror.SafeParams(map[string]any{
		"tokenAcquiredTime": r.tokenData.tokenAcquiredTime,
		"tokenTTL":          r.tokenTTL,
	})
	if r.tokenData.token == "" {
		return "", werror.Wrap(r.tokenData.tokenAcquireError, "all attempts to retrieve a token have failed", errorParam)
	}
	if time.Now().Sub(r.tokenData.tokenAcquiredTime) > r.tokenTTL {
		if r.tokenData.tokenAcquireError != nil {
			return "", werror.Wrap(r.tokenData.tokenAcquireError, "token is expired, attempts to obtain new token have failed", errorParam)
		}
		return "", werror.Wrap(r.tokenData.tokenAcquireError, "token is expired, attempts to obtain new token have not completed", errorParam)
	}
	// otherwise we have a token that is usable, even if the last attempt to get a token failed
	return r.tokenData.token, nil
}

func (r *Refresher) waitForInitialized(ctx context.Context) error {
	// Fast path: avoid creating a timer if initialization has already completed.
	select {
	case <-r.tokenDataInitialized:
		return nil
	default:
	}

	waitCtx, cancel := context.WithTimeout(ctx, r.initTimeout)
	defer cancel()

	select {
	case <-waitCtx.Done():
		r.tokenDataLock.RLock()
		lastErr := r.tokenData.tokenAcquireError
		r.tokenDataLock.RUnlock()
		params := werror.SafeParam("initTimeout", r.initTimeout.String())
		if lastErr != nil {
			return werror.WrapWithContextParams(waitCtx, lastErr, "timed out waiting for initial token acquisition",
				werror.SafeParam("ctxErr", waitCtx.Err().Error()), params)
		}
		return werror.WrapWithContextParams(waitCtx, waitCtx.Err(), "timed out waiting for initial token acquisition", params)
	case <-r.tokenDataInitialized:
		return nil
	}
}

// TokenTTL returns the TTL of the token.
func (r *Refresher) TokenTTL() time.Duration {
	return r.tokenTTL
}

// Run starts an endless refresh loop and is a blocking call; this will return once the context is cancelled.
func (r *Refresher) Run(ctx context.Context) {
	// divide by two so we get a new token ahead of expiry
	refreshInterval := r.tokenTTL / 2
	fuzzyTicker := retry.Start(ctx,
		retry.WithInitialBackoff(refreshInterval),
		retry.WithMaxBackoff(refreshInterval),
		retry.WithRandomizationFactor(0.2),
	)

	for fuzzyTicker.Next() {
		_ = retry.Do(ctx, func() error {
			svc1log.FromContext(ctx).Debug("Attempting to retrieve token from provider.")
			token, err := r.provideToken(ctx)
			if err != nil {
				svc1log.FromContext(ctx).Error("Failed to refresh token, retrying.", svc1log.Stacktrace(err))
			}
			r.updateToken(token, err)
			return err
		})
	}
}

func (r *Refresher) updateToken(token string, err error) {
	r.tokenDataLock.Lock()
	defer r.tokenDataLock.Unlock()
	var newTokenData tokenData
	if err == nil {
		newTokenData = tokenData{
			token:             token,
			tokenAcquiredTime: time.Now(),
			tokenAcquireError: nil,
		}
		// close channel on first successful token acquisition
		select {
		case <-r.tokenDataInitialized:
		default:
			close(r.tokenDataInitialized)
		}
	} else {
		newTokenData = tokenData{
			token:             r.tokenData.token,
			tokenAcquiredTime: r.tokenData.tokenAcquiredTime,
			tokenAcquireError: err,
		}
	}
	r.tokenData = newTokenData
}
