/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"github.com/shaj13/go-guardian/v2/auth"
	jwtStrategy "github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
)

type JwtAuthz struct {
	JwtSecretKeeper jwtStrategy.SecretsKeeper
	AuthZStrategy   auth.Strategy
}

type AuthTokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
