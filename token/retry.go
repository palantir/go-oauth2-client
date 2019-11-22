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

	"github.com/palantir/pkg/retry"
	werror "github.com/palantir/witchcraft-go-error"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// NewRetryingTokenProvider takes a TokenProvider and uses it to create another TokenProvider that retries forever.
func NewRetryingTokenProvider(provideToken Provider) Provider {
	return func(ctx context.Context) (string, error) {
		var numAttempts int
		var token string
		var err error
		err = retry.Do(ctx, func() error {
			token, err = provideToken(ctx)
			if err == nil {
				return nil
			}
			svc1log.FromContext(ctx).Error(
				"failed to get new token; will try again",
				svc1log.SafeParam("numAttempts", numAttempts),
				svc1log.Stacktrace(err))
			numAttempts++
			return err
		})
		if err != nil {
			return "", werror.Wrap(
				err,
				"token retrieval timed out",
				werror.SafeParam("numAttempts", numAttempts))
		}
		return token, nil
	}
}
