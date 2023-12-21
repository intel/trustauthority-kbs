/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package repository

import (
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository/directory"

	"github.com/google/uuid"
)

type (
	KeyStore interface {
		Create(*model.KeyAttributes) (*model.KeyAttributes, error)
		Update(*model.KeyAttributes) (*model.KeyAttributes, error)
		Retrieve(uuid.UUID) (*model.KeyAttributes, error)
		Delete(uuid.UUID) error
		Search(criteria *model.KeyFilterCriteria) ([]model.KeyAttributes, error)
	}

	KeyTransferPolicyStore interface {
		Create(attributes *model.KeyTransferPolicy) (*model.KeyTransferPolicy, error)
		Retrieve(uuid.UUID) (*model.KeyTransferPolicy, error)
		Delete(uuid.UUID) error
		Search(criteria *model.KeyTransferPolicyFilterCriteria) ([]model.KeyTransferPolicy, error)
	}

	UserStore interface {
		Create(user *model.UserInfo) (*model.UserInfo, error)
		Retrieve(uuid.UUID) (*model.UserInfo, error)
		Delete(uuid.UUID) error
		Search(criteria *model.UserFilterCriteria) ([]model.UserInfo, error)
		Update(user *model.UserInfo) (*model.UserInfo, error)
	}
)

type Repository struct {
	KeyStore               KeyStore
	KeyTransferPolicyStore KeyTransferPolicyStore
	UserStore              UserStore
}

func NewDirectoryRepository(basePath string) *Repository {
	return &Repository{
		KeyStore:               directory.NewKeyStore(basePath + constant.KeysDir),
		KeyTransferPolicyStore: directory.NewKeyTransferPolicyStore(basePath + constant.KeysTransferPolicyDir),
		UserStore:              directory.NewUserStore(basePath + constant.UserDir),
	}
}
