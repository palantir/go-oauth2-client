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

package oauth

import (
	"context"
	"net/http"
	"net/url"

	"github.com/palantir/conjure-go-runtime/conjure-go-client/httpclient"
	"github.com/palantir/conjure-go-runtime/conjure-go-contract/codecs"
	"github.com/palantir/witchcraft-go-error"
)

const (
	clientCredentialsEndpoint  = "/oauth2/token"
	clientCredentialsGrantType = "client_credentials"
)

type serviceClient struct {
	client                   httpclient.Client
	clientCredentialEndpoint string
}

type oauth2Response struct {
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
}

// NewClientCredentialClient returns an oauth2.Client configured using the provided client.
// The client will use the httpclient's configured BaseURIs.
func NewClientCredentialClient(client httpclient.Client) ClientCredentialClient {
	return &serviceClient{
		client: client,
	}
}

func (s *serviceClient) CreateClientCredentialToken(ctx context.Context, clientID, clientSecret string) (string, error) {
	urlValues := url.Values{
		"grant_type":    []string{clientCredentialsGrantType},
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	var oauth2Resp oauth2Response
	_, err := s.client.Do(ctx,
		httpclient.WithRPCMethodName("CreateClientCredentialToken"),
		httpclient.WithRequestMethod(http.MethodPost),
		httpclient.WithPath(clientCredentialsEndpoint),
		httpclient.WithRequestBody(urlValues, codecs.FormURLEncoded),
		httpclient.WithJSONResponse(&oauth2Resp),
	)
	if err != nil {
		return "", werror.Wrap(err, "failed to make create client credential token request")
	}
	return oauth2Resp.AccessToken, nil
}
