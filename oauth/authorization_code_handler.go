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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"

	"github.com/Masterminds/goutils"
	werror "github.com/palantir/witchcraft-go-error"
	"github.com/pkg/browser"
)

const (
	authorizeApplicationPath = "oauth2/authorize"
)

var (
	redirectURL = url.URL{
		Scheme: "http",
		Host:   "localhost:8401",
		Path:   "/redirect",
	}
)

// AuthorizationCodeHandler handles the callback part of Authorization Code flow
type AuthorizationCodeHandler interface {
	PromptAndWaitForCode(ctx context.Context) (*AuthorizationCode, error)
}

// AuthorizationCode is a response returned from a callback in Authorization Code flow
type AuthorizationCode struct {
	Code         string
	CodeVerifier string
	ClientID     string
}

type authorizationCodeHandler struct {
	clientID     string
	loginBaseURL string
}

// NewAuthorizationCodeHandler returns a new Authorization Code flow handler with a localhost callback listener
// Expects loginBaseURL to point to a base URL of the OAuth login provider
func NewAuthorizationCodeHandler(clientID string, loginBaseURL string) AuthorizationCodeHandler {
	return &authorizationCodeHandler{
		clientID:     clientID,
		loginBaseURL: loginBaseURL,
	}
}

// PromptAndWaitForCode opens a login URL in the browser, starts a local webserver listening on port 8401 for the OAuth callback,
// and returns the obtained authorization code once it is received by the callback
func (h *authorizationCodeHandler) PromptAndWaitForCode(ctx context.Context) (*AuthorizationCode, error) {
	l, err := net.Listen("tcp", redirectURL.Host)
	if err != nil {
		return nil, werror.WrapWithContextParams(ctx, err, "failed to create callback handling server")
	}

	resultsCh := make(chan string)
	errorsCh := make(chan error)
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(redirectURL.Path, newRedirectHandler(resultsCh, errorsCh))

	s := &http.Server{Handler: serveMux}
	go func() {
		errorsCh <- s.Serve(l)
	}()

	defer func() {
		_ = s.Close()
	}()

	codeVerifier, err := goutils.CryptoRandomAlphaNumeric(64)
	if err != nil {
		return nil, werror.WrapWithContextParams(ctx, err, "failed to generate code verifier")
	}
	codeVerifierHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeVerifierHash[:])
	initialLoginURL, err := url.Parse(h.loginBaseURL)
	if err != nil {
		return nil, werror.WrapWithContextParams(ctx, err, "failed to parse login URL")
	}
	initialLoginURL.Path = path.Join(initialLoginURL.Path, authorizeApplicationPath)
	initialLoginURL.RawQuery = url.Values{
		"response_type":         {"code"},
		"client_id":             {h.clientID},
		"redirect_uri":          {redirectURL.String()},
		"code_verifier":         {codeVerifier},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	if err := browser.OpenURL(initialLoginURL.String()); err != nil {
		return nil, werror.WrapWithContextParams(ctx, err, "failed to open browser for auth")
	}

	var code string
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errorsCh:
		return nil, werror.WrapWithContextParams(ctx, err, "could not complete auth handshake")
	case code = <-resultsCh:
		break
	}

	return &AuthorizationCode{
		Code:         code,
		CodeVerifier: codeVerifier,
		ClientID:     h.clientID,
	}, nil
}

func newRedirectHandler(resultsCh chan<- string, errorsCh chan<- error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("code")
		if token == "" {
			errorsCh <- errors.New("did not receive token")
		}
		if _, err := fmt.Fprint(w, "You have successfully signed into your account.\nYou can close this window and continue using the product."); err != nil {
			errorsCh <- werror.Wrap(err, "failed to write response")
		}
		resultsCh <- token
	}
}
