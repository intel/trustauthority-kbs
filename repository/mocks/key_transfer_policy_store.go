/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package mocks

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"intel/amber/kbs/v1/repository/directory"
	"reflect"
	"time"

	"intel/amber/kbs/v1/model"
	cns "intel/amber/kbs/v1/repository/mocks/constants"
)

// MockKeyTransferPolicyStore provides a mocked implementation of interface domain.KeyTransferPolicyStore
type MockKeyTransferPolicyStore struct {
	KeyTransferPolicyStore map[uuid.UUID]*model.KeyTransferPolicy
}

// Create inserts a KeyTransferPolicy into the store
func (store *MockKeyTransferPolicyStore) Create(p *model.KeyTransferPolicy) (*model.KeyTransferPolicy, error) {
	store.KeyTransferPolicyStore[p.ID] = p
	return p, nil
}

// Retrieve returns a single KeyTransferPolicy record from the store
func (store *MockKeyTransferPolicyStore) Retrieve(id uuid.UUID) (*model.KeyTransferPolicy, error) {
	if p, ok := store.KeyTransferPolicyStore[id]; ok {
		return p, nil
	}
	return nil, errors.New(directory.RecordNotFound)
}

// Update KeyTransferPolicy record in the store
func (store *MockKeyTransferPolicyStore) Update(policy *model.KeyTransferPolicy) (*model.KeyTransferPolicy, error) {
	if p, ok := store.KeyTransferPolicyStore[policy.ID]; ok {
		store.KeyTransferPolicyStore[p.ID] = policy
		return p, nil
	}
	return nil, errors.New("Record Not Found")
}

// Delete deletes KeyTransferPolicy from the store
func (store *MockKeyTransferPolicyStore) Delete(id uuid.UUID) error {
	if _, ok := store.KeyTransferPolicyStore[id]; ok {
		delete(store.KeyTransferPolicyStore, id)
		return nil
	}
	return errors.New("Record Not Found")
}

// Search returns a filtered list of KeyTransferPolicies per the provided KeyTransferPolicyFilterCriteria
func (store *MockKeyTransferPolicyStore) Search(criteria *model.KeyTransferPolicyFilterCriteria) ([]model.KeyTransferPolicy, error) {

	var policies []model.KeyTransferPolicy
	// start with all records
	for _, p := range store.KeyTransferPolicyStore {
		policies = append(policies, *p)
	}

	// KeyTransferPolicy filter is false
	if criteria == nil || reflect.DeepEqual(*criteria, model.KeyTransferPolicyFilterCriteria{}) {
		return policies, nil
	}

	return policies, nil
}

// NewFakeKeyTransferPolicyStore loads dummy data into MockKeyTransferPolicyStore
func NewFakeKeyTransferPolicyStore() *MockKeyTransferPolicyStore {
	store := &MockKeyTransferPolicyStore{}
	store.KeyTransferPolicyStore = make(map[uuid.UUID]*model.KeyTransferPolicy)
	var falVar bool = false

	var i uint16 = 0
	_, err := store.Create(&model.KeyTransferPolicy{
		ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		CreatedAt:       time.Now().UTC(),
		AttestationType: []model.AttesterType{model.SGX},
		SGX: &model.SgxPolicy{
			PolicyIds: []uuid.UUID{uuid.MustParse("232bffd9-7ab3-4bb5-bc6c-1852123d1a01")},
			Attributes: &model.SgxAttributes{
				MrSigner:           []string{cns.ValidMrSigner},
				IsvProductId:       []uint16{1},
				MrEnclave:          []string{cns.ValidMrEnclave},
				IsvSvn:             &i,
				ClientPermissions:  []string{"nginx", "USA"},
				EnforceTCBUptoDate: &falVar,
			},
		},
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key transfer policy")
	}

	_, err = store.Create(&model.KeyTransferPolicy{
		ID:              uuid.MustParse("73755fda-c910-46be-821f-e8ddeab189e9"),
		CreatedAt:       time.Now().UTC(),
		AttestationType: []model.AttesterType{model.SGX},
		SGX: &model.SgxPolicy{
			Attributes: &model.SgxAttributes{
				MrSigner:           []string{cns.ValidMrSigner},
				IsvProductId:       []uint16{1},
				MrEnclave:          []string{cns.ValidMrEnclave},
				IsvSvn:             &i,
				ClientPermissions:  []string{"nginx", "USA"},
				EnforceTCBUptoDate: nil,
			},
		},
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key transfer policy")
	}

	var j uint8 = 0

	_, err = store.Create(&model.KeyTransferPolicy{
		ID:              uuid.MustParse("f64e25de-634f-44a3-b520-db480d8781ce"),
		CreatedAt:       time.Now().UTC(),
		AttestationType: []model.AttesterType{model.TDX},
		TDX: &model.TdxPolicy{
			Attributes: &model.TdxAttributes{
				MrSignerSeam:       []string{cns.ValidMrSignerSeam},
				MrSeam:             []string{cns.ValidMrSeam},
				SeamSvn:            &j,
				MRTD:               []string{cns.ValidMRTD},
				RTMR0:              cns.ValidRTMR0,
				RTMR1:              cns.ValidRTMR1,
				RTMR2:              cns.ValidRTMR2,
				RTMR3:              cns.ValidRTMR3,
				EnforceTCBUptoDate: &falVar,
			},
		},
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key transfer policy")
	}
	return store
}
