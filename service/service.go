/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"context"
	"fmt"
	jwtStrategy "github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
	"github.com/shaj13/libcache"
	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/jwt"
	"intel/amber/kbs/v1/keymanager"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository"
	"intel/amber/kbs/v1/version"
	"time"

	"github.com/google/uuid"
)

type Service interface {
	CreateKey(context.Context, model.KeyRequest) (*model.KeyResponse, error)
	SearchKeys(context.Context, *model.KeyFilterCriteria) ([]*model.KeyResponse, error)
	DeleteKey(context.Context, uuid.UUID) (interface{}, error)
	UpdateKey(context.Context, model.KeyUpdateRequest) (*model.KeyResponse, error)
	RetrieveKey(context.Context, uuid.UUID) (interface{}, error)
	CreateKeyTransferPolicy(context.Context, model.KeyTransferPolicy) (*model.KeyTransferPolicy, error)
	SearchKeyTransferPolicies(context.Context, *model.KeyTransferPolicyFilterCriteria) ([]model.KeyTransferPolicy, error)
	DeleteKeyTransferPolicy(context.Context, uuid.UUID) (interface{}, error)
	RetrieveKeyTransferPolicy(context.Context, uuid.UUID) (interface{}, error)
	TransferKey(context.Context, TransferKeyRequest) (*TransferKeyResponse, error)
	TransferKeyWithEvidence(context.Context, TransferKeyRequest) (*TransferKeyResponse, error)
	CreateUser(context.Context, *model.User) (*model.UserResponse, error)
	UpdateUser(context.Context, *model.UpdateUserRequest) (*model.UserResponse, error)
	SearchUser(context.Context, *model.UserFilterCriteria) ([]model.UserResponse, error)
	DeleteUser(context.Context, uuid.UUID) (interface{}, error)
	RetrieveUser(context.Context, uuid.UUID) (interface{}, error)
	GetVersion(context.Context) (*version.ServiceVersion, error)
	CreateAuthToken(context.Context, model.AuthTokenRequest, *model.JwtAuthz) (string, error)
}

type service struct {
	asClient      as.ASClient
	jwtVerifier   jwt.Verifier
	repository    *repository.Repository
	remoteManager *keymanager.RemoteManager
	config        *config.Configuration
}

func NewService(asClient as.ASClient, jwtVerifier jwt.Verifier, repo *repository.Repository, remoteManager *keymanager.RemoteManager, config *config.Configuration) (Service, error) {

	var svc Service
	{
		svc = service{
			asClient:      asClient,
			jwtVerifier:   jwtVerifier,
			repository:    repo,
			remoteManager: remoteManager,
			config:        config,
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

func SetupAuthZ(jwtKeeper *jwtStrategy.StaticSecret) (*model.JwtAuthz, error) {
	cache := libcache.FIFO.New(0)
	cache.SetTTL(time.Minute * 5)

	opt := token.SetScopes(token.NewScope(constant.KeyTransferPolicyCreate, "/key-transfer-policies", "POST"),
		token.NewScope(constant.KeyTransferPolicySearch, "/key-transfer-policies", "GET"),
		token.NewScope(constant.KeyTransferPolicyDelete, "/key-transfer-policies", "DELETE"),
		token.NewScope(constant.KeyCreate, "/keys", "POST"),
		token.NewScope(constant.KeySearch, "/keys", "GET"),
		token.NewScope(constant.KeyDelete, "/keys", "DELETE"),
		token.NewScope(constant.KeyUpdate, "/keys", "PUT"),
		token.NewScope(constant.KeyTransfer, "/keys/"+constant.UUIDReg, "POST"),
		token.NewScope(constant.UserCreate, "/users", "POST"),
		token.NewScope(constant.UserSearch, "/users", "GET"),
		token.NewScope(constant.UserUpdate, "/users", "PUT"),
		token.NewScope(constant.UserDelete, "/users", "DELETE"))
	strategy := jwtStrategy.New(cache, jwtKeeper, opt)

	jwtAuth := model.JwtAuthz{
		JwtSecretKeeper: jwtKeeper,
		AuthZStrategy:   strategy,
	}
	return &jwtAuth, nil
}
