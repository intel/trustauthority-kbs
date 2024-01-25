/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package directory

import (
	"crypto/subtle"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"intel/kbs/v1/model"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

type userStore struct {
	dir string
}

func NewUserStore(dir string) *userStore {
	return &userStore{dir}
}

func (u *userStore) Create(user *model.UserInfo) (*model.UserInfo, error) {

	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	user.CreatedAt = time.Now().UTC()
	bytes, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Wrap(err, "directory/user_store:Create() Failed to marshal user attributes")
	}

	err = os.WriteFile(filepath.Clean(filepath.Join(u.dir, user.ID.String())), bytes, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "directory/user_store:Create() Failed to store user attributes in file")
	}

	return user, nil
}

func (u *userStore) Retrieve(userID uuid.UUID) (*model.UserInfo, error) {

	bytes, err := os.ReadFile(filepath.Clean(filepath.Join(u.dir, userID.String())))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New(RecordNotFound)
		} else {
			return nil, errors.Wrapf(err, "directory/user_store:Retrieve() Unable to read user file : %s", userID.String())
		}
	}

	var user model.UserInfo
	err = json.Unmarshal(bytes, &user)
	if err != nil {
		return nil, errors.Wrap(err, "directory/user_store:Retrieve() Failed to unmarshal user attributes")
	}

	return &user, nil
}

func (u *userStore) Delete(userID uuid.UUID) error {

	if err := os.Remove(filepath.Join(u.dir, userID.String())); err != nil {
		if os.IsNotExist(err) {
			return errors.New(RecordNotFound)
		} else {
			return errors.Wrapf(err, "directory/user_store:Delete() Unable to remove user file : %s", userID.String())
		}
	}
	return nil
}

func (u *userStore) Search(criteria *model.UserFilterCriteria) ([]model.UserInfo, error) {

	var users = []model.UserInfo{}
	userFiles, err := os.ReadDir(u.dir)
	if err != nil {
		return nil, errors.Wrapf(err, "directory/user_store:Search() Error in reading the users directory : %s", u.dir)
	}

	for _, userFile := range userFiles {
		filename, err := uuid.Parse(userFile.Name())
		if err != nil {
			return nil, errors.Wrapf(err, "directory/user_store:Search() Error in parsing user file name : %s", userFile.Name())
		}
		user, err := u.Retrieve(filename)
		if err != nil {
			return nil, errors.Wrapf(err, "directory/user_store:Search() Error in retrieving user from file : %s", userFile.Name())
		}
		users = append(users, *user)
	}

	if criteria == nil || reflect.DeepEqual(*criteria, model.UserFilterCriteria{}) {
		return users, nil
	}

	if criteria.Username != "" {
		for _, user := range users {
			unameMatched := subtle.ConstantTimeCompare([]byte(user.Username), []byte(criteria.Username))
			if unameMatched == 1 {
				return []model.UserInfo{user}, nil
			}
		}
	}

	return []model.UserInfo{}, nil
}

func (u *userStore) Update(user *model.UserInfo) (*model.UserInfo, error) {

	// read the existing user file
	existingUserFile, err := os.OpenFile(filepath.Clean(filepath.Join(u.dir, user.ID.String())), os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, errors.Wrapf(err, "directory/user_store:Update() Error in updating user with ID : %s", user.ID)
	}
	user.UpdatedAt = time.Now().UTC()
	bytes, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Wrap(err, "directory/user_store:Update() Failed to marshal user attributes")
	}
	// writing the new user info into existing file
	_, err = existingUserFile.Write(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "directory/user_store:Update() Failed to write user info into the file")
	}
	return user, nil
}
