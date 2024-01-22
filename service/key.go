/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"context"
	"crypto/sha512"
	"github.com/sirupsen/logrus"
	"intel/kbs/v1/constant"
	"net/http"
	"time"

	"intel/kbs/v1/model"

	"github.com/google/uuid"
)

const (
	RowsNotFound   = "no rows in result set"
	RecordNotFound = "record not found"
)

func (mw loggingMiddleware) CreateKey(ctx context.Context, req model.KeyRequest) (*model.KeyResponse, error) {
	log = logrus.WithField("user", ctx.Value(constant.LogUserID))
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
		_, err := svc.repository.KeyTransferPolicyStore.Retrieve(keyCreateReq.TransferPolicyID)
		if err != nil {
			if err.Error() == RecordNotFound {
				log.Errorf("Key transfer policy with specified id could not be located")
				return nil, &HandledError{Code: http.StatusBadRequest, Message: "Key transfer policy with specified id does not exist"}
			}
			log.WithError(err).Error("Key transfer policy retrieve failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve key transfer policy"}
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

func (mw loggingMiddleware) UpdateKey(ctx context.Context, request model.KeyUpdateRequest) (*model.KeyResponse, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("UpdateKey took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.UpdateKey(ctx, request)
	return resp, err
}

func (svc service) UpdateKey(ctx context.Context, keyUpdateReq model.KeyUpdateRequest) (*model.KeyResponse, error) {
	var err error
	// check if the key transfer policy exists
	if keyUpdateReq.TransferPolicyID != uuid.Nil {
		transferPolicy, err := svc.repository.KeyTransferPolicyStore.Retrieve(keyUpdateReq.TransferPolicyID)
		if err != nil || transferPolicy == nil {
			log.WithError(err).Error("Key transfer policy retrieve failed")
			return nil, &HandledError{Code: http.StatusBadRequest, Message: "Failed to retrieve key transfer policy"}
		}
	} else {
		log.WithError(err).Error("Key transfer policy must be provided")
		return nil, &HandledError{Code: http.StatusBadRequest, Message: "Key transfer policy must be provided"}
	}

	updatedKey, err := svc.remoteManager.UpdateKey(&keyUpdateReq)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.WithError(err).Errorf("Key update request failed, key with ID %s not found", keyUpdateReq.KeyId.String())
			return nil, &HandledError{Code: http.StatusNotFound, Message: "Failed to update key with the given key transfer policy ID. Invalid keyID."}
		} else {
			log.WithError(err).Error("Key update request failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to update key with the given key transfer policy ID"}
		}
	}
	return updatedKey, err

}

func (mw loggingMiddleware) TransferKey(ctx context.Context, req TransferKeyRequest) (*TransferKeyResponse, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("TransferKey took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.TransferKey(ctx, req)
	return resp, err
}

func (svc service) TransferKey(_ context.Context, req TransferKeyRequest) (*TransferKeyResponse, error) {
	secretKey, status, err := getSecretKey(svc.remoteManager, req.KeyId)
	if err != nil {
		return nil, &HandledError{Code: status, Message: err.Error()}
	}

	// Wrap secret key with public key
	wrappedKey, status, err := wrapKey(req.PublicKey, secretKey.([]byte), sha512.New384(), nil)
	if err != nil {
		return nil, &HandledError{Code: status, Message: err.Error()}
	}

	transferResponse := &model.KeyTransferResponse{
		WrappedKey: wrappedKey.([]byte),
	}
	resp := &TransferKeyResponse{
		KeyTransferResponse: transferResponse,
	}
	return resp, nil
}
