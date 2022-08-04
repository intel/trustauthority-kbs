/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	defaultLog "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"intel/amber/kbs/v1/model"
	"reflect"
	"time"
)

// MockUserStore provides a mocked implementation of interface domain.UserStore
type MockUserStore struct {
	mock.Mock
	UserStore map[uuid.UUID]*model.UserInfo
}

// Create inserts a user into the store
func (store *MockUserStore) Create(u *model.UserInfo) (*model.UserInfo, error) {
	store.UserStore[u.ID] = u
	return u, nil
}

// Retrieve returns a single user record from the store
func (store *MockUserStore) Retrieve(id uuid.UUID) (*model.UserInfo, error) {
	if k, ok := store.UserStore[id]; ok {
		return k, nil
	}
	return nil, errors.New("Record not found")
}

// Delete deletes user from the store
func (store *MockUserStore) Delete(id uuid.UUID) error {
	if _, ok := store.UserStore[id]; ok {
		delete(store.UserStore, id)
		return nil
	}
	return errors.New("Record not found")
}

func (store *MockUserStore) Search(criteria *model.UserFilterCriteria) ([]model.UserInfo, error) {
	var users []model.UserInfo
	// start with all records
	for _, u := range store.UserStore {
		users = append(users, *u)
	}

	if criteria == nil || reflect.DeepEqual(*criteria, model.UserFilterCriteria{}) {
		return users, nil
	}

	if criteria.Username != "" {
		for _, user := range users {
			if user.Username == criteria.Username {
				return []model.UserInfo{user}, nil
			}
		}
	}

	return []model.UserInfo{}, nil
}

// Update inserts a user into the store
func (store *MockUserStore) Update(u *model.UserInfo) (*model.UserInfo, error) {
	store.UserStore[u.ID] = u
	return u, nil
}

// NewFakeUserStore loads dummy data into MockUserStore
func NewFakeUserStore() *MockUserStore {
	store := &MockUserStore{}
	store.UserStore = make(map[uuid.UUID]*model.UserInfo)

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("adminPassword"), bcrypt.DefaultCost)
	if err != nil {
		defaultLog.WithError(err).Error("Error while generating the hash of the password")
	}

	_, err = store.Create(&model.UserInfo{
		ID:           uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Time{},
		Username:     "adminUser",
		PasswordHash: passwordHash,
		PasswordCost: 0,
		Permissions:  nil,
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating user")
	}

	passwordHash, err = bcrypt.GenerateFromPassword([]byte("keyRetrievePassword"), bcrypt.DefaultCost)
	if err != nil {
		defaultLog.WithError(err).Error("Error while generating the hash of the password")
	}

	_, err = store.Create(&model.UserInfo{
		ID:           uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Time{},
		Username:     "keyRetrieveUser",
		PasswordHash: passwordHash,
		PasswordCost: 0,
		Permissions:  nil,
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating user")
	}

	passwordHash, err = bcrypt.GenerateFromPassword([]byte("keyManagerPassword"), bcrypt.DefaultCost)
	if err != nil {
		defaultLog.WithError(err).Error("Error while generating the hash of the password")
	}

	_, err = store.Create(&model.UserInfo{
		ID:           uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Time{},
		Username:     "keyManager",
		PasswordHash: passwordHash,
		PasswordCost: 0,
		Permissions:  nil,
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating user")
	}

	passwordHash, err = bcrypt.GenerateFromPassword([]byte("userAdminPassword"), bcrypt.DefaultCost)
	if err != nil {
		defaultLog.WithError(err).Error("Error while generating the hash of the password")
	}

	_, err = store.Create(&model.UserInfo{
		ID:           uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Time{},
		Username:     "userAdmin",
		PasswordHash: passwordHash,
		PasswordCost: 0,
		Permissions:  nil,
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating user")
	}

	passwordHash, err = bcrypt.GenerateFromPassword([]byte("keyTransferPolicyUserPassword"), bcrypt.DefaultCost)
	if err != nil {
		defaultLog.WithError(err).Error("Error while generating the hash of the password")
	}

	_, err = store.Create(&model.UserInfo{
		ID:           uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Time{},
		Username:     "keyTransferPolicyUser",
		PasswordHash: passwordHash,
		PasswordCost: 0,
		Permissions:  nil,
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating user")
	}

	return store
}
