<p align="right">
<a href="https://autorelease.general.dmz.palantir.tech/palantir/go-oauth2-client"><img src="https://img.shields.io/badge/Perform%20an-Autorelease-success.svg" alt="Autorelease"></a>
</p>

# go-oauth-client

[![CircleCI](https://circleci.com/gh/palantir/go-oauth2-client/tree/develop.svg?style=svg)](https://circleci.com/gh/palantir/go-oauth2-client/tree/develop) [![](https://godoc.org/github.com/palantir/go-oauth2-client?status.svg)](http://godoc.org/github.com/palantir/go-oauth2-client)

A Golang client for requesting an access token from an OAuth2 server.

Support the following auth flows:
1. Client Credentials Flow. See the [OAuth2 `client_credentials` specification](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/) for details.
2. Authorization Code Flow. See the [OAuth2 `authorization_code` specification](https://www.oauth.com/oauth2-servers/access-tokens/authorization-code-request/) for details.

## License
This project is made available under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
