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
	"encoding/json"
	"io"
	"net/http"

	werror "github.com/palantir/witchcraft-go-error"
	wparams "github.com/palantir/witchcraft-go-params"
)

const (
	oauthTokenEndpoint = "/oauth2/token"
)

type oauth2Response struct {
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
}

type errorDecoder struct {
	ctx context.Context
}

func (errorDecoder) Handles(resp *http.Response) bool {
	return resp != nil && resp.Body != nil && resp.StatusCode > 399
}

func (d errorDecoder) DecodeError(resp *http.Response) error {
	ctx := wparams.ContextWithSafeParam(d.ctx, "statusCode", resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return werror.WrapWithContextParams(ctx, err, "server returned an error and failed to read body")
	}
	if len(body) == 0 {
		return werror.ErrorWithContextParams(ctx, resp.Status)
	}
	var errObj oauth2Error
	if err := json.Unmarshal(body, &errObj); err != nil {
		return werror.WrapWithContextParams(ctx, err, "server returned an error and failed to unmarshal body",
			werror.UnsafeParam("responseBody", string(body)))
	} else if errObj.ErrorType == "" {
		return werror.ErrorWithContextParams(ctx, "server returned an error and failed to unmarshal body",
			werror.UnsafeParam("responseBody", string(body)))
	}
	return werror.ErrorWithContextParams(ctx, resp.Status, werror.Params(errObj))
}

// oauth2Error implements the JSON structure defined in RFC 6749 Section 5.2.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type oauth2Error struct {
	ErrorType        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

func (e oauth2Error) SafeParams() map[string]interface{} {
	return map[string]interface{}{"oauthError": e.ErrorType}
}

func (e oauth2Error) UnsafeParams() map[string]interface{} {
	m := map[string]interface{}{}
	if e.ErrorDescription != "" {
		m["oauthErrorDescription"] = e.ErrorDescription
	}
	if e.ErrorURI != "" {
		m["oauthErrorUri"] = e.ErrorURI
	}
	return m
}
