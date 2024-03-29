/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"bytes"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"strings"
)

type Token struct {
	jwtToken       *jwt.Token
	standardClaims *jwt.StandardClaims
	customClaims   interface{}
}

func GetTokenClaims(parsedToken *jwt.Token, tokenString string, customClaims interface{}) (*Token, error) {

	token := Token{}
	token.standardClaims = &jwt.StandardClaims{}
	token.jwtToken = parsedToken

	// so far we have only got the standardClaims parsed. We need to now fill the customClaims
	parts := strings.Split(tokenString, ".")

	// parse Claims
	var claimBytes []byte
	var err error

	if claimBytes, err = jwt.DecodeSegment(parts[1]); err != nil {
		return nil, errors.Wrap(err, "could not decode claims part of the jwt token")
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	err = dec.Decode(customClaims)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode token claims as json")
	}
	token.customClaims = customClaims

	return &token, nil
}
