/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"context"
	"fmt"

	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/jwt"
	"intel/amber/kbs/v1/keymanager"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository"
	"intel/amber/kbs/v1/version"

	"github.com/google/uuid"
)

type Service interface {
	CreateKey(context.Context, model.KeyRequest) (*model.KeyResponse, error)
	SearchKeys(context.Context, *model.KeyFilterCriteria) ([]*model.KeyResponse, error)
	DeleteKey(context.Context, uuid.UUID) (interface{}, error)
	RetrieveKey(context.Context, uuid.UUID) (interface{}, error)
	CreateKeyTransferPolicy(context.Context, model.KeyTransferPolicy) (*model.KeyTransferPolicy, error)
	SearchKeyTransferPolicies(context.Context, *model.KeyTransferPolicyFilterCriteria) ([]model.KeyTransferPolicy, error)
	DeleteKeyTransferPolicy(context.Context, uuid.UUID) (interface{}, error)
	RetrieveKeyTransferPolicy(context.Context, uuid.UUID) (interface{}, error)
	TransferKey(context.Context, TransferKeyRequest) (*TransferKeyResponse, error)
	GetVersion(context.Context) (*version.ServiceVersion, error)
}

type service struct {
	asClient      as.ASClient
	jwtVerifier   jwt.Verifier
	repository    *repository.Repository
	remoteManager *keymanager.RemoteManager
}

func NewService(asClient as.ASClient, jwtVerifier jwt.Verifier, repo *repository.Repository, remoteManager *keymanager.RemoteManager) (Service, error) {

	var svc Service
	{
		svc = service{
			asClient:      asClient,
			jwtVerifier:   jwtVerifier,
			repository:    repo,
			remoteManager: remoteManager,
		}
	}

	svc = LoggingMiddleware()(svc)
	return svc, nil
}

type HandledError struct {
	Code    int
	Message string
}

func (e HandledError) StatusCode() int {
	return e.Code
}

func (e HandledError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}
