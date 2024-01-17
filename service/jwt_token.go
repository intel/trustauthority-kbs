/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */

package service

import (
	"context"
	"crypto/rand"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"intel/kbs/v1/model"
	"math/big"
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
		// introducing random delay to prevent authentication timing vulnerability in case of invalid user.
		secureRandomDelay()
		return "", &HandledError{Code: http.StatusBadRequest, Message: "Invalid username or password"}
	}
	// match the password against the store passwordHash
	err = bcrypt.CompareHashAndPassword(users[0].PasswordHash, []byte(request.Password))
	if err != nil {
		log.WithError(err).Error("Password does not match for the given user")
		return "", &HandledError{Code: http.StatusBadRequest, Message: "Invalid username or password"}
	}
	// generate token
	u := auth.NewUserInfo(request.Username, users[0].ID.String(), nil, nil)
	ns := jwt.SetNamedScopes(users[0].Permissions...)
	tokenExp := time.Duration(svc.config.BearerTokenValidityInMinutes) * time.Minute
	exp := jwt.SetExpDuration(tokenExp)
	token, err := jwt.IssueAccessToken(u, jwtAuth.JwtSecretKeeper, ns, exp)
	if err != nil {
		log.WithError(err).Error("Error while generating a token")
		return "", &HandledError{Code: http.StatusInternalServerError, Message: "Error while generating a token"}
	}
	return token, err
}

// secureRandomDelay introduces a cryptographically secure random delay between min and max durations.
// this change was introduced to fix authentication timing vulnerability.
func secureRandomDelay() {
	// the minTim and maxTime is calculated based on the average difference between a valid request and invalid request
	minTime := 170 * time.Millisecond
	maxTime := 210 * time.Millisecond
	// Generate a random number in the range [0, max-min)
	randomDelay, err := rand.Int(rand.Reader, big.NewInt(int64(maxTime-minTime)))
	if err != nil {
		// fall back to default delay
		time.Sleep(time.Duration(170 * time.Millisecond))
	}
	// adding minTime to the random delay to ensure that the final delay is between range[min,max]
	delay := time.Duration(randomDelay.Int64()) + minTime
	time.Sleep(delay)
}
