/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */

package mocks

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	defaultLog "github.com/sirupsen/logrus"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository/directory"
	"reflect"
	"time"
)

// MockKeyStore provides a mocked implementation of interface domain.KeyStore
type MockKeyStore struct {
	KeyStore map[uuid.UUID]*model.KeyAttributes
}

// Create inserts a Key into the store
func (store *MockKeyStore) Create(k *model.KeyAttributes) (*model.KeyAttributes, error) {
	store.KeyStore[k.ID] = k
	return k, nil
}

// Retrieve returns a single Key record from the store
func (store *MockKeyStore) Retrieve(id uuid.UUID) (*model.KeyAttributes, error) {
	if k, ok := store.KeyStore[id]; ok {
		return k, nil
	}
	return nil, errors.New(directory.RecordNotFound)
}

// Delete deletes Key from the store
func (store *MockKeyStore) Delete(id uuid.UUID) error {
	if _, ok := store.KeyStore[id]; ok {
		delete(store.KeyStore, id)
		return nil
	}
	return errors.New("Record not found")
}

// Search returns a filtered list of Keys per the provided KeyFilterCriteria
func (store *MockKeyStore) Search(criteria *model.KeyFilterCriteria) ([]model.KeyAttributes, error) {

	var keys []model.KeyAttributes
	// start with all records
	for _, k := range store.KeyStore {
		keys = append(keys, *k)
	}

	if criteria == nil {
		return keys, nil
	}

	// Key filter is false
	if reflect.DeepEqual(*criteria, model.KeyFilterCriteria{}) {
		return keys, errors.New("Invalid search criteria")
	}

	// Algorithm filter
	if criteria.Algorithm != "" {
		var kFiltered []model.KeyAttributes
		for _, k := range keys {
			if k.Algorithm == criteria.Algorithm {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// KeyLength filter
	if criteria.KeyLength != 0 {
		var kFiltered []model.KeyAttributes
		for _, k := range keys {
			if k.KeyLength == criteria.KeyLength {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// CurveType filter
	if criteria.CurveType != "" {
		var kFiltered []model.KeyAttributes
		for _, k := range keys {
			if k.CurveType == criteria.CurveType {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// TransferPolicyId filter
	if criteria.TransferPolicyId != uuid.Nil {
		var kFiltered []model.KeyAttributes
		for _, k := range keys {
			if k.TransferPolicyId == criteria.TransferPolicyId {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	return keys, nil
}

// NewFakeKeyStore loads dummy data into MockKeyStore
func NewFakeKeyStore() *MockKeyStore {
	store := &MockKeyStore{}
	store.KeyStore = make(map[uuid.UUID]*model.KeyAttributes)

	_, err := store.Create(&model.KeyAttributes{
		ID:               uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "1",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "/kbs/v1/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating key attributes")
	}

	_, err = store.Create(&model.KeyAttributes{
		ID:               uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "4",
		TransferPolicyId: uuid.MustParse("f64e25de-634f-44a3-b520-db480d8781ce"),
		TransferLink:     "/kbs/v1/keys/ed37c360-7eae-4250-a677-6ee12adce8e3/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating key attributes")
	}

	_, err = store.Create(&model.KeyAttributes{
		ID:               uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		Algorithm:        "EC",
		CurveType:        "prime256v1",
		KmipKeyID:        "2",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "/kbs/v1/keys/e57e5ea0-d465-461e-882d-1600090caa0d/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating key attributes")
	}

	_, err = store.Create(&model.KeyAttributes{
		ID:               uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
		Algorithm:        "RSA",
		KeyLength:        2048,
		KmipKeyID:        "3",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "/kbs/v1/keys/87d59b82-33b7-47e7-8fcb-6f7f12c82719/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating key attributes")
	}

	return store
}
