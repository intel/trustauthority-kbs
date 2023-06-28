/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */

package service

import (
	"context"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"intel/amber/kbs/v1/model"
	"net/http"
	"time"
)

func (mw loggingMiddleware) CreateUser(ctx context.Context, createUserRequest *model.User) (*model.UserResponse, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("CreateUser took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.CreateUser(ctx, createUserRequest)
	return resp, err
}

func (svc service) CreateUser(ctx context.Context, createUserRequest *model.User) (*model.UserResponse, error) {
	// check if a user with same name exists already
	existingUsers, err := svc.repository.UserStore.Search(&model.UserFilterCriteria{Username: createUserRequest.Username})
	if err != nil {
		log.WithError(err).Error("Error search for a user with given filter criteria")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Error searching for a user with the given name before creating"}
	} else if len(existingUsers) != 0 {
		log.Error("Error search for a user with given filter criteria before trying to create a new user")
		return nil, &HandledError{Code: http.StatusBadRequest, Message: "User with same username already exists"}
	}

	// generate the hash of the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(createUserRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		log.WithError(err).Error("Error while generating the hash of the password")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Error while generating the hash of the password"}
	}
	// TODO: evaluate permissions with * regex
	user := &model.UserInfo{
		ID:           uuid.New(),
		Username:     createUserRequest.Username,
		PasswordHash: passwordHash,
		PasswordCost: bcrypt.DefaultCost,
		Permissions:  createUserRequest.Permissions,
	}
	user, err = svc.repository.UserStore.Create(user)
	if err != nil {
		log.WithError(err).Error("Error while creating a user")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Error creating a user"}
	}
	log.Debugf("Successfully created a user with name %s", user.Username)
	return getUserResponseFromUserInfo(user), nil
}

func (mw loggingMiddleware) UpdateUser(ctx context.Context, updateUserReq *model.UpdateUserRequest) (*model.UserResponse, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("UpdateUser took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.UpdateUser(ctx, updateUserReq)
	return resp, err
}

func (svc service) UpdateUser(ctx context.Context, updateUserReq *model.UpdateUserRequest) (*model.UserResponse, error) {
	// check if the user with the given ID exists
	user, err := svc.repository.UserStore.Retrieve(updateUserReq.ID)
	if user == nil || err != nil {
		log.Errorf("user with the given ID does not exist. Failed to update user %s", updateUserReq.ID.String())
		return nil, &HandledError{Code: http.StatusBadRequest, Message: "user with the given ID does not exist"}
	}

	if updateUserReq.UpdateUser.Username != "" {
		// check if the given username is already taken
		existingUsers, err := svc.repository.UserStore.Search(&model.UserFilterCriteria{Username: updateUserReq.UpdateUser.Username})
		if err != nil {
			log.WithError(err).Error("Error search for a user with given filter criteria")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Error searching for a user with the given name before updating"}
		} else if len(existingUsers) != 0 && existingUsers[0].ID != updateUserReq.ID {
			log.Error("Error search for a user with given filter criteria")
			return nil, &HandledError{Code: http.StatusBadRequest, Message: "User with same username already exists"}
		}
		user.Username = updateUserReq.UpdateUser.Username
	}
	if len(updateUserReq.UpdateUser.Permissions) != 0 {
		user.Permissions = updateUserReq.UpdateUser.Permissions
	}
	if updateUserReq.UpdateUser.Password != "" {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(updateUserReq.UpdateUser.Password), bcrypt.DefaultCost)
		if err != nil {
			log.WithError(err).Error("Error while generating the hash of the password")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Error while generating the hash of the password"}
		}
		user.PasswordHash = passwordHash
	}
	updatedUser, err := svc.repository.UserStore.Update(user)
	if err != nil {
		log.WithError(err).Error("Error while updating the user")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Error updating the user"}
	}
	log.Debugf("Successfully updated the user with ID %s", updatedUser.ID.String())
	return getUserResponseFromUserInfo(updatedUser), nil
}

func (mw loggingMiddleware) SearchUser(ctx context.Context, userFilterCriteria *model.UserFilterCriteria) ([]model.UserResponse, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("SearchUser took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.SearchUser(ctx, userFilterCriteria)
	return resp, err
}

func (svc service) SearchUser(ctx context.Context, userFilterCriteria *model.UserFilterCriteria) ([]model.UserResponse, error) {
	users, err := svc.repository.UserStore.Search(userFilterCriteria)
	if err != nil {
		log.WithError(err).Error("Error search for a user with given filter criteria")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Error searching for a user with given filter criteria"}
	}
	userResp := []model.UserResponse{}
	for _, user := range users {
		userResp = append(userResp, *getUserResponseFromUserInfo(&user))
	}
	return userResp, nil
}

func (mw loggingMiddleware) DeleteUser(ctx context.Context, userID uuid.UUID) (interface{}, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("DeleteUser took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.DeleteUser(ctx, userID)
	return resp, err
}

func (svc service) DeleteUser(ctx context.Context, userID uuid.UUID) (interface{}, error) {
	err := svc.repository.UserStore.Delete(userID)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.Error("User with specified id could not be located")
			return nil, &HandledError{Code: http.StatusNotFound, Message: "User with specified id does not exist"}
		} else {
			log.WithError(err).Error("User delete failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to delete User"}
		}
	}
	return nil, nil
}

func (mw loggingMiddleware) RetrieveUser(ctx context.Context, userID uuid.UUID) (interface{}, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("RetrieveUser took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.RetrieveUser(ctx, userID)
	return resp, err
}

func (svc service) RetrieveUser(ctx context.Context, userID uuid.UUID) (interface{}, error) {
	user, err := svc.repository.UserStore.Retrieve(userID)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.Error("User with specified id could not be located")
			return nil, &HandledError{Code: http.StatusNotFound, Message: "User with specified id does not exist"}
		} else {
			log.WithError(err).Error("User retrieve failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve User"}
		}
	}
	return getUserResponseFromUserInfo(user), nil
}

func getUserResponseFromUserInfo(userInfo *model.UserInfo) *model.UserResponse {
	return &model.UserResponse{
		ID:          userInfo.ID,
		CreatedAt:   userInfo.CreatedAt,
		UpdatedAt:   userInfo.UpdatedAt,
		Username:    userInfo.Username,
		Permissions: userInfo.Permissions,
	}
}
