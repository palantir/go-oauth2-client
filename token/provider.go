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
	"time"

	"github.com/palantir/conjure-go-runtime/v2/conjure-go-client/httpclient"
	"github.com/palantir/go-oauth2-client/v2/oauth"
)

// Provider accepts a context and returns either:
//
// (1) a nonempty token and a nil error, or
//
// (2) an empty string and a non-nil error.
type Provider = httpclient.TokenProvider

// CreateAndStartRefreshingOAuthProvider returns a Provider which caches and periodically refreshes a client token.
// When it returns, we have not yet necessarily successfully fetched a valid token.
func CreateAndStartRefreshingOAuthProvider(ctx context.Context, client oauth.ClientCredentialClient, clientID, clientSecret string, refreshInterval time.Duration) Provider {
	refresher := NewRefresher(func(ctx context.Context) (string, error) {
		return client.CreateClientCredentialToken(ctx, clientID, clientSecret)
	}, refreshInterval)
	go refresher.Run(ctx)
	return refresher.Token
}
