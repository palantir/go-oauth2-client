// Copyright (c) 2022 Palantir Technologies. All rights reserved.
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

package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/palantir/conjure-go-runtime/v2/conjure-go-client/httpclient"
	"github.com/palantir/conjure-go-runtime/v2/conjure-go-contract/codecs"
	"github.com/palantir/conjure-go-runtime/v2/conjure-go-contract/errors"
	"github.com/palantir/conjure-go-runtime/v2/conjure-go-server/httpserver"
	werror "github.com/palantir/witchcraft-go-error"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	ctx := context.Background()
	const (
		userName   = "user"
		userSecret = "secret"
	)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body := url.Values{}
		err := codecs.FormURLEncoded.Decode(req.Body, &body)
		assert.NoError(t, err)
		if body.Get("client_id") == userName && body.Get("client_secret") == userSecret {
			_, err = rw.Write([]byte(`{"access_token":"token"}`))
			assert.NoError(t, err)
		} else {
			rw.WriteHeader(400)
			_, err = rw.Write([]byte(`{"error":"invalid_client", "error_description":"Client authentication failed"}`))
			assert.NoError(t, err)
		}
	}))
	defer tokenSrv.Close()

	tokenHTTPClient, err := httpclient.NewClient(httpclient.WithBaseURLs([]string{tokenSrv.URL}))
	require.NoError(t, err)
	tokenClient := NewClientCredentialClient(tokenHTTPClient)
	goodTokenProvider := func(ctx context.Context) (string, error) {
		return tokenClient.CreateClientCredentialToken(ctx, userName, userSecret)
	}
	badTokenProvider := func(ctx context.Context) (string, error) {
		return tokenClient.CreateClientCredentialToken(ctx, "bad-user", "bad-secret")
	}

	t.Run("success", func(t *testing.T) {
		token, err := goodTokenProvider(ctx)
		require.NoError(t, err)
		assert.Equal(t, "token", token)
	})
	t.Run("error", func(t *testing.T) {
		token, err := badTokenProvider(ctx)
		assert.Empty(t, token)
		require.EqualError(t, err, "failed to make create client credential token request: httpclient request failed: 400 Bad Request")
		safe, unsafe := werror.ParamsFromError(err)
		assert.EqualValues(t, 400, safe["statusCode"])
		assert.EqualValues(t, "invalid_client", safe["oauthError"])
		assert.EqualValues(t, "Client authentication failed", unsafe["oauthErrorDescription"])
	})
	// Use client as a token provider for a different API expecting a bearer token
	t.Run("TokenProvider", func(t *testing.T) {
		verifySrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			token, err := httpserver.ParseBearerTokenHeader(req)
			if err != nil {
				errors.WriteErrorResponse(rw, errors.WrapWithUnauthorized(err))
				return
			}
			if token != "token" {
				errors.WriteErrorResponse(rw, errors.NewPermissionDenied())
				return
			}
			rw.WriteHeader(200)
		}))
		defer verifySrv.Close()

		t.Run("no token", func(t *testing.T) {
			verifyClient, err := httpclient.NewClient(httpclient.WithBaseURLs([]string{verifySrv.URL}))
			require.NoError(t, err)
			_, err = verifyClient.Get(ctx)
			require.Error(t, err)
			require.Contains(t, err.Error(), "httpclient request failed: UNAUTHORIZED Default:Unauthorized")
			status, ok := httpclient.StatusCodeFromError(err)
			require.True(t, ok)
			require.Equal(t, 401, status)
		})

		t.Run("bad token", func(t *testing.T) {
			verifyClient, err := httpclient.NewClient(httpclient.WithBaseURLs([]string{verifySrv.URL}),
				httpclient.WithAuthTokenProvider(func(ctx context.Context) (string, error) {
					return "bad", nil
				}))
			require.NoError(t, err)
			_, err = verifyClient.Get(ctx)
			require.Error(t, err)
			require.Contains(t, err.Error(), "httpclient request failed: PERMISSION_DENIED Default:PermissionDenied")
			status, ok := httpclient.StatusCodeFromError(err)
			require.True(t, ok)
			require.Equal(t, 403, status)
		})

		t.Run("bad secret", func(t *testing.T) {
			verifyClient, err := httpclient.NewClient(httpclient.WithBaseURLs([]string{verifySrv.URL}),
				httpclient.WithAuthTokenProvider(badTokenProvider))
			require.NoError(t, err)
			_, err = verifyClient.Get(ctx)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to make create client credential token request")
			safe, unsafe := werror.ParamsFromError(err)
			assert.EqualValues(t, 400, safe["statusCode"])
			assert.EqualValues(t, "invalid_client", safe["oauthError"])
			assert.EqualValues(t, "Client authentication failed", unsafe["oauthErrorDescription"])
		})

		t.Run("good token", func(t *testing.T) {
			verifyClient, err := httpclient.NewClient(httpclient.WithBaseURLs([]string{verifySrv.URL}),
				httpclient.WithAuthTokenProvider(goodTokenProvider))
			require.NoError(t, err)
			_, err = verifyClient.Get(ctx)
			require.NoError(t, err)
		})
	})
}
