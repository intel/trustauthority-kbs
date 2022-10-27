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
	// User account username for which authentication token is required
	// required: true
	// example: testUser
	Username string `json:"username"`
	// User account password for which authentication token is required
	// required: true
	// example: testPassword
	Password string `json:"password"`
}
