// Copyright (c) 2023 Palantir Technologies. All rights reserved.
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
	"net/url"

	"github.com/palantir/conjure-go-runtime/v2/conjure-go-client/httpclient"
	"github.com/palantir/conjure-go-runtime/v2/conjure-go-contract/codecs"
	werror "github.com/palantir/witchcraft-go-error"
)

const (
	authorizationCodeGrantType = "authorization_code"
)

type authorizationCodeClient struct {
	client httpclient.Client
}

// NewAuthorizationCodeClient returns an AuthorizationCodeClient configured using the provided client.
func NewAuthorizationCodeClient(client httpclient.Client) AuthorizationCodeClient {
	return &authorizationCodeClient{
		client: client,
	}
}

// AuthorizationCodeTokenRequest contains parameters in the request to get token in Authorization Code flow
type AuthorizationCodeTokenRequest struct {
	ClientID     string
	Code         string
	CodeVerifier string
	RedirectURI  string
}

// URLValues returns url.Values representation of AuthorizationCodeTokenRequest
func (r AuthorizationCodeTokenRequest) URLValues() url.Values {
	values := url.Values{
		"grant_type":    []string{authorizationCodeGrantType},
		"client_id":     []string{r.ClientID},
		"code":          []string{r.Code},
		"code_verifier": []string{r.CodeVerifier},
	}

	if r.RedirectURI != "" {
		values.Set("redirect_uri", r.RedirectURI)
	}
	return values
}

func (c *authorizationCodeClient) CreateAuthorizationCodeToken(ctx context.Context, req AuthorizationCodeTokenRequest) (string, error) {
	var oauth2Resp oauth2Response
	_, err := c.client.Do(ctx,
		httpclient.WithRPCMethodName("CreateAuthorizationCodeToken"),
		httpclient.WithRequestMethod(http.MethodPost),
		httpclient.WithPath(oauthTokenEndpoint),
		httpclient.WithRequestBody(req.URLValues(), codecs.FormURLEncoded),
		httpclient.WithJSONResponse(&oauth2Resp),
		httpclient.WithRequestErrorDecoder(errorDecoder{ctx}),
	)
	if err != nil {
		return "", werror.WrapWithContextParams(ctx, err, "failed to make create authorization code token request")
	}
	return oauth2Resp.AccessToken, nil
}
