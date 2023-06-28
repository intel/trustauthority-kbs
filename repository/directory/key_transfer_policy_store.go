/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package directory

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"intel/amber/kbs/v1/model"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type keyTransferPolicyStore struct {
	dir string
}

func NewKeyTransferPolicyStore(dir string) *keyTransferPolicyStore {
	return &keyTransferPolicyStore{dir}
}

func (ktps *keyTransferPolicyStore) Create(policy *model.KeyTransferPolicy) (*model.KeyTransferPolicy, error) {

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_transfer_policy_store:Create() failed to create new UUID")
	}
	policy.ID = newUuid
	policy.CreatedAt = time.Now().UTC()
	bytes, err := json.Marshal(policy)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_transfer_policy_store:Create() Failed to marshal key transfer policy")
	}

	err = ioutil.WriteFile(filepath.Join(ktps.dir, policy.ID.String()), bytes, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_transfer_policy_store:Create() Error in saving key transfer policy")
	}

	return policy, nil
}

func (ktps *keyTransferPolicyStore) Retrieve(id uuid.UUID) (*model.KeyTransferPolicy, error) {

	bytes, err := ioutil.ReadFile(filepath.Join(ktps.dir, id.String()))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New(RecordNotFound)
		} else {
			return nil, errors.Wrapf(err, "directory/key_transfer_policy_store:Retrieve() Unable to read key transfer policy file : %s", id.String())
		}
	}

	var policy model.KeyTransferPolicy
	err = json.Unmarshal(bytes, &policy)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_transfer_policy_store:Retrieve() Failed to unmarshal key transfer policy")
	}

	return &policy, nil
}

func (ktps *keyTransferPolicyStore) Delete(id uuid.UUID) error {

	if err := os.Remove(filepath.Join(ktps.dir, id.String())); err != nil {
		if os.IsNotExist(err) {
			return errors.New(RecordNotFound)
		} else {
			return errors.Wrapf(err, "directory/key_transfer_policy_store:Delete() Unable to remove key transfer policy file : %s", id.String())
		}
	}

	return nil
}

func (ktps *keyTransferPolicyStore) Search(criteria *model.KeyTransferPolicyFilterCriteria) ([]model.KeyTransferPolicy, error) {

	var policies = []model.KeyTransferPolicy{}
	policyFiles, err := ioutil.ReadDir(ktps.dir)
	if err != nil {
		return nil, errors.New("directory/key_transfer_policy_store:Search() Unable to read the key transfer policy directory")
	}

	for _, policyFile := range policyFiles {
		filename, err := uuid.Parse(policyFile.Name())
		if err != nil {
			return nil, errors.Wrapf(err, "directory/key_transfer_policy_store:Search() Error in parsing policy file name : %s", policyFile.Name())
		}
		policy, err := ktps.Retrieve(filename)
		if err != nil {
			return nil, errors.Wrapf(err, "directory/key_transfer_policy_store:Search() Error in retrieving policy from file : %s", policyFile.Name())
		}

		policies = append(policies, *policy)
	}

	if len(policies) > 0 {
		policies = filterKeyTransferPolicies(policies, criteria)
	}

	return policies, nil
}

// helper function to filter the key transfer policies based on given filter criteria.
func filterKeyTransferPolicies(policies []model.KeyTransferPolicy, criteria *model.KeyTransferPolicyFilterCriteria) []model.KeyTransferPolicy {

	if criteria == nil || reflect.DeepEqual(*criteria, model.KeyTransferPolicyFilterCriteria{}) {
		return policies
	}
	return policies
}
