/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package jwt

import (
	"github.com/golang-jwt/jwt"
)

type StandardClaims jwt.StandardClaims
type CustomClaims interface{}

type claims struct {
	jwt.StandardClaims
	customClaims interface{}
}

type Token struct {
	jwtToken       *jwt.Token
	standardClaims *jwt.StandardClaims
	customClaims   interface{}
}

func (t *Token) GetClaims() interface{} {
	return t.customClaims
}

func (t *Token) GetAllClaims() interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return t.jwtToken.Claims
}

func (t *Token) GetStandardClaims() interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return t.standardClaims
}

func (t *Token) GetHeader() *map[string]interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return &t.jwtToken.Header
}

func (t *Token) GetSubject() string {
	if t.standardClaims == nil {
		return ""
	}
	return t.standardClaims.Subject
}