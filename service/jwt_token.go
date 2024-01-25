/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"crypto/rand"
	"github.com/pkg/errors"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"intel/kbs/v1/defender"
	"intel/kbs/v1/model"
	"math/big"
	"net/http"
	"time"
)

var defend *defender.Defender

func InitDefender(maxAttempts, intervalMins, lockoutDurationMins int) {
	defend = defender.New(maxAttempts,
		time.Duration(intervalMins)*time.Minute,
		time.Duration(lockoutDurationMins)*time.Minute)

	defend.Cleanup()
}

func (mw loggingMiddleware) CreateAuthToken(ctx context.Context, request model.AuthTokenRequest, jwtAuth *model.JwtAuthz) (string, error) {
	log = logrus.WithField("user", request.Username)
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
		return "", &HandledError{Code: http.StatusUnauthorized, Message: "Invalid username or password"}
	}

	// check if this user is banned or allowed to retrieve a token
	errorCode, err := checkIfUserBanned(users[0], request.Password)
	if err != nil || errorCode != 0 {
		return "", &HandledError{Code: errorCode, Message: err.Error()}
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

func checkIfUserBanned(user model.UserInfo, passwordProvided string) (int, error) {
	// first let us make sure that this is not a user that is banned

	log.Debug("Checking if the user is banned")
	foundInDefendList := false
	// check if we have an entry for the client in the defend map.
	// There are several scenarios in this case
	if client, ok := defend.Client(user.Username); ok {
		foundInDefendList = true
		if client.Banned() {
			// case 1. Client is banned - however, the ban expired but cleanup is not done.
			// just delete the client from the map
			if client.BanExpired() {
				defend.RemoveClient(client.Key())
			} else {
				log.Error("user is banned due to exceeded number of invalid attempts to get authorization token")
				return http.StatusTooManyRequests, errors.Errorf("maximum login attempts exceeded for user : %s. Banned ", user.Username)
			}
		}
	}

	// match the password against the store passwordHash
	err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(passwordProvided))
	if err != nil {
		log.WithError(err).Error("Password does not match for the given user")
		// increment the count in case of invalid password, returns true if the user is banned after maxAttempt login
		if defend.Inc(user.Username) {
			log.Error("user is banned due to exceeded number of invalid attempts to get authorization token")
			return http.StatusTooManyRequests, errors.Errorf("authentication failure - maximum login attempts exceeded for user : %s. Banned ", user.Username)
		}
		return http.StatusUnauthorized, errors.Errorf("invalid username or password provided")
	}
	// If we found the user earlier in the defend list, we should now remove as user is authorized
	if foundInDefendList {
		if client, ok := defend.Client(user.Username); ok {
			defend.RemoveClient(client.Key())
		}
	}
	return 0, nil
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
