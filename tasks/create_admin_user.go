/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"intel/kbs/v1/repository"
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

	// check if a user with same name exists already
	existingUsers, err := ac.UserStore.Search(&model.UserFilterCriteria{Username: ac.AdminUsername})
	if len(existingUsers) != 0 {
		log.Warnf("Failed to create admin user. User with same username %s already exists", ac.AdminUsername)
		return nil
	} else if err != nil {
		log.WithError(err).Errorf("Error search for a user with given username %s", ac.AdminUsername)
		return errors.New("Error searching for a user before creating a new admin user")
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

	log.Infof("Successfully created an admin user with name %s", user.Username)
	return nil
}
