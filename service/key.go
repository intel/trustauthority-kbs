/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"context"
	"net/http"
	"time"

	"intel/amber/kbs/v1/model"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	RowsNotFound   = "no rows in result set"
	RecordNotFound = "record not found"
)

func (mw loggingMiddleware) CreateKey(ctx context.Context, req model.KeyRequest) (*model.KeyResponse, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("CreateKey took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.CreateKey(ctx, req)
	return resp, err
}

func (svc service) CreateKey(_ context.Context, keyCreateReq model.KeyRequest) (*model.KeyResponse, error) {

	if keyCreateReq.TransferPolicyID != uuid.Nil {
		transferPolicy, err := svc.repository.KeyTransferPolicyStore.Retrieve(keyCreateReq.TransferPolicyID)
		if err != nil {
			log.WithError(err).Error("Key transfer policy retrieve failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve key transfer policy"}
		}

		if transferPolicy == nil {
			log.Errorf("Key transfer policy with specified id could not be located")
			return nil, &HandledError{Code: http.StatusBadRequest, Message: "Key transfer policy with specified id does not exist"}
		}
	}

	var err error
	var createdKey *model.KeyResponse
	if keyCreateReq.KeyInfo.KeyData == "" && keyCreateReq.KeyInfo.KmipKeyID == "" {

		log.Debug("Create key request received")
		createdKey, err = svc.remoteManager.CreateKey(&keyCreateReq)
		if err != nil {
			log.WithError(err).Error("Key create failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to create key"}
		}
	} else {

		log.Debug("Register key request received")
		createdKey, err = svc.remoteManager.RegisterKey(&keyCreateReq)
		if err != nil {
			log.WithError(err).Error("Key register failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to register key"}
		}
	}
	return createdKey, nil
}

func (mw loggingMiddleware) SearchKeys(ctx context.Context, kfc *model.KeyFilterCriteria) ([]*model.KeyResponse, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("SearchKey took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.SearchKeys(ctx, kfc)
	return resp, err
}

func (svc service) SearchKeys(_ context.Context, filter *model.KeyFilterCriteria) ([]*model.KeyResponse, error) {

	keys, err := svc.remoteManager.SearchKeys(filter)
	if err != nil {
		log.WithError(err).Error("Key search failed")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to search keys"}
	}
	return keys, nil
}

func (mw loggingMiddleware) DeleteKey(ctx context.Context, id uuid.UUID) (interface{}, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("DeleteKey took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.DeleteKey(ctx, id)
	return resp, err
}

func (svc service) DeleteKey(_ context.Context, keyId uuid.UUID) (interface{}, error) {
	err := svc.remoteManager.DeleteKey(keyId)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.Error("Key with specified id could not be located")
			return nil, &HandledError{Code: http.StatusNotFound, Message: "Key with specified id does not exist"}
		} else {
			log.WithError(err).Error("Key delete failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to delete key"}
		}
	}
	return nil, nil
}

func (mw loggingMiddleware) RetrieveKey(ctx context.Context, id uuid.UUID) (interface{}, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("RetrieveKey took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.RetrieveKey(ctx, id)
	return resp, err
}

func (svc service) RetrieveKey(_ context.Context, keyId uuid.UUID) (interface{}, error) {
	key, err := svc.remoteManager.RetrieveKey(keyId)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.Error("Key with specified id could not be located")
			return nil, &HandledError{Code: http.StatusNotFound, Message: "Key with specified id does not exist"}
		} else {
			log.WithError(err).Error("Key retrieve failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve key"}
		}
	}

	return key, nil
}
