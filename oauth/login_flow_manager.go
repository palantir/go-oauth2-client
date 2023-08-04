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
)

// AuthorizationCodeLoginFlowManager performs Authorization Code login flow
type AuthorizationCodeLoginFlowManager interface {
	// PerformLoginFlow performs Authorization Code login flow and returns a token if successful
	PerformLoginFlow(ctx context.Context) (string, error)
}

type authorizationCodeLoginFlowManager struct {
	Client  AuthorizationCodeClient
	Handler AuthorizationCodeHandler
}

// NewAuthorizationCodeLoginFlowManager creates a new Authorization Code login flow manager
func NewAuthorizationCodeLoginFlowManager(client AuthorizationCodeClient, handler AuthorizationCodeHandler) AuthorizationCodeLoginFlowManager {
	return &authorizationCodeLoginFlowManager{
		Client:  client,
		Handler: handler,
	}
}

// PerformLoginFlow performs Authorization Code login flow and returns a token if successful
func (m *authorizationCodeLoginFlowManager) PerformLoginFlow(ctx context.Context) (string, error) {
	resp, err := m.Handler.PromptAndWaitForCode(ctx)
	if err != nil {
		return "", err
	}
	token, err := m.Client.CreateAuthorizationCodeToken(ctx, AuthorizationCodeTokenRequest{
		ClientID:     resp.ClientID,
		Code:         resp.Code,
		CodeVerifier: resp.CodeVerifier,
		RedirectURI:  DefaultCallbackURL.String(),
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
