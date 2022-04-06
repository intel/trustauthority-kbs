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

func (mw loggingMiddleware) CreateKeyTransferPolicy(ctx context.Context, ktp model.KeyTransferPolicy) (*model.KeyTransferPolicy, error) {
	var err error
	defer func(begin time.Time) {
		log.Infof("CreateKeyTransferPolicy took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.CreateKeyTransferPolicy(ctx, ktp)
	return resp, err
}

func (svc service) CreateKeyTransferPolicy(_ context.Context, policyCreateRequest model.KeyTransferPolicy) (*model.KeyTransferPolicy, error) {

	createdPolicy, err := svc.repository.KeyTransferPolicyStore.Create(&policyCreateRequest)
	if err != nil {
		log.WithError(err).Error("Key transfer policy create failed")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to create key transfer policy"}
	}

	return createdPolicy, nil
}

func (mw loggingMiddleware) RetrieveKeyTransferPolicy(ctx context.Context, id uuid.UUID) (interface{}, error) {
	var err error
	defer func(begin time.Time) {
		log.Infof("RetrieveKeyTransferPolicy took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.RetrieveKeyTransferPolicy(ctx, id)
	return resp, err
}

func (svc service) RetrieveKeyTransferPolicy(_ context.Context, id uuid.UUID) (interface{}, error) {

	transferPolicy, err := svc.repository.KeyTransferPolicyStore.Retrieve(id)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.Errorf("Key transfer policy with specified id could not be located")
			return nil, &HandledError{Code: http.StatusNotFound, Message: "Key transfer policy with specified id does not exist"}
		} else {
			log.WithError(err).Error("Key transfer policy retrieve failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve key transfer policy"}
		}
	}

	return transferPolicy, nil
}

func (mw loggingMiddleware) DeleteKeyTransferPolicy(ctx context.Context, id uuid.UUID) (interface{}, error) {
	var err error
	defer func(begin time.Time) {
		log.Infof("DeleteKeyTransferPolicy took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.DeleteKeyTransferPolicy(ctx, id)
	return resp, err
}

func (svc service) DeleteKeyTransferPolicy(_ context.Context, id uuid.UUID) (interface{}, error) {

	criteria := &model.KeyFilterCriteria{
		TransferPolicyId: id,
	}

	keys, err := svc.repository.KeyStore.Search(criteria)
	if err != nil {
		log.WithError(err).Error("Key search failed")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to search keys"}
	}

	if len(keys) > 0 {
		log.Error("Key transfer policy is associated with existing keys")
		return nil, &HandledError{Code: http.StatusBadRequest, Message: "Key transfer policy is associated with keys"}
	}

	err = svc.repository.KeyTransferPolicyStore.Delete(id)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.Error("Key transfer policy with specified id could not be located")
			return nil, &HandledError{Code: http.StatusNotFound, Message: "Key transfer policy with specified id does not exist"}
		} else {
			log.WithError(err).Error("Key transfer policy delete failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to delete key transfer policy"}
		}
	}

	return nil, nil
}

func (mw loggingMiddleware) SearchKeyTransferPolicies(ctx context.Context, pfc *model.KeyTransferPolicyFilterCriteria) ([]model.KeyTransferPolicy, error) {
	var err error
	defer func(begin time.Time) {
		log.Infof("SearchKeyTransferPolicy took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.SearchKeyTransferPolicies(ctx, pfc)
	return resp, err
}

func (svc service) SearchKeyTransferPolicies(_ context.Context, filter *model.KeyTransferPolicyFilterCriteria) ([]model.KeyTransferPolicy, error) {

	transferPolicies, err := svc.repository.KeyTransferPolicyStore.Search(filter)
	if err != nil {
		log.WithError(err).Error("Key transfer policy search failed")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to search key transfer policies"}
	}

	return transferPolicies, nil
}
