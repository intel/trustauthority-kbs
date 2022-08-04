/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/model"
	"net/http"
	"time"
)

func (mw loggingMiddleware) CreateAuthToken(ctx context.Context, request model.AuthTokenRequest, jwtAuth *model.JwtAuthz) (string, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("CreateAuthToken took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.CreateAuthToken(ctx, request, jwtAuth)
	return resp, err
}

func (svc service) CreateAuthToken(ctx context.Context, request model.AuthTokenRequest, jwtAuth *model.JwtAuthz) (string, error) {

	// check if username and password are provided
	if request.Username == "" || request.Password == "" {
		log.Error("Username or password cannot be empty")
		return "", &HandledError{Code: http.StatusBadRequest, Message: "Username and password of a valid user must be provided to get the token"}
	}

	// check if user exists
	users, err := svc.repository.UserStore.Search(&model.UserFilterCriteria{Username: request.Username})
	if len(users) == 0 || err != nil {
		log.WithError(err).Error("Error search for a user with given filter criteria")
		return "", &HandledError{Code: http.StatusBadRequest, Message: "User with given name does not exist"}
	}
	// match the password against the store passwordHash
	err = bcrypt.CompareHashAndPassword(users[0].PasswordHash, []byte(request.Password))
	if err != nil {
		log.WithError(err).Error("Password does not match for the given user")
		return "", &HandledError{Code: http.StatusBadRequest, Message: "Password does not match for the given user"}
	}
	// generate token
	u := auth.NewUserInfo(request.Username, users[0].ID.String(), nil, nil)
	ns := jwt.SetNamedScopes(users[0].Permissions...)
	exp := jwt.SetExpDuration(constant.DefaultTokenExpiration)
	token, err := jwt.IssueAccessToken(u, jwtAuth.JwtSecretKeeper, ns, exp)
	if err != nil {
		log.WithError(err).Error("Error while generating a token")
		return "", &HandledError{Code: http.StatusInternalServerError, Message: "Error while generating a token"}
	}
	return token, err
}
