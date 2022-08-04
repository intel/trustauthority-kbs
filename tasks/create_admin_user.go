/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository"
)

type CreateAdminUser struct {
	AdminUsername string
	AdminPassword string
	UserStore     repository.UserStore
}

func (ac *CreateAdminUser) CreateAdminUser() error {
	log.Info("Creating an admin user")
	if ac.AdminUsername == "" || ac.AdminPassword == "" {
		return errors.New("Admin username or password cannot be empty")
	}
	// generate the hash of the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(ac.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "Error while generating the hash of the password")
	}

	user := &model.UserInfo{
		ID:           uuid.New(),
		Username:     ac.AdminUsername,
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Permissions:  constant.AdminPermissions,
	}
	user, err = ac.UserStore.Create(user)
	if err != nil {
		return errors.Wrap(err, "Error creating a user")
	}

	log.Debugf("Successfully created an admin user with name %s", user.Username)
	return nil
}
