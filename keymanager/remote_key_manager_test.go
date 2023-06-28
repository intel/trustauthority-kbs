/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package keymanager

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/kmipclient"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository"
	"intel/amber/kbs/v1/repository/mocks"
)

func TestRemoteManagerCreateKey(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	keyManager := NewKmipManager(mockClient)

	policyId, _ := uuid.Parse("3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9")

	keyStore = mocks.NewFakeKeyStore()
	type fields struct {
		store   repository.KeyStore
		manager KeyManager
	}
	type args struct {
		request *model.KeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *model.KeyResponse
		wantErr bool
	}{
		{
			name: "Validate create key with valid input, should create a new key",
			fields: fields{
				store:   keyStore,
				manager: keyManager,
			},
			args: args{
				request: &model.KeyRequest{
					KeyInfo: &model.KeyInfo{
						Algorithm: "AES",
						KeyLength: 256,
					},
					TransferPolicyID: policyId,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:   tt.fields.store,
				manager: tt.fields.manager,
			}
			_, err := rm.CreateKey(tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRemoteManagerRetrieveKey(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	keyStore = mocks.NewFakeKeyStore()

	type fields struct {
		store   repository.KeyStore
		manager KeyManager
	}
	type args struct {
		keyId uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *model.KeyResponse
		wantErr bool
	}{
		{
			name: "Validate retrieve key with valid input, should retrieve a key",
			fields: fields{
				store:   keyStore,
				manager: keyManager,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			},
			wantErr: false,
		},
		{
			name: "Validate retrieve key with invalid keyid, should fail to retrieve a key",
			fields: fields{
				store:   keyStore,
				manager: keyManager,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e3"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:   tt.fields.store,
				manager: tt.fields.manager,
			}

			_, err := rm.RetrieveKey(tt.args.keyId)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.RetrieveKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRemoteManagerDeleteKey(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	keyStore = mocks.NewFakeKeyStore()
	type fields struct {
		store   repository.KeyStore
		manager KeyManager
	}
	type args struct {
		keyId uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Validate delete key with valid input, should delete a key",
			fields: fields{
				store:   keyStore,
				manager: keyManager,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			},
			wantErr: false,
		},
		{
			name: "Validate delete key with invalid keyid, should fail to delete a key",
			fields: fields{
				store:   keyStore,
				manager: keyManager,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce9a3"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:   tt.fields.store,
				manager: tt.fields.manager,
			}
			if err := rm.DeleteKey(tt.args.keyId); (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.DeleteKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoteManagerSearchKeys(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	keyStore = mocks.NewFakeKeyStore()

	type fields struct {
		store   repository.KeyStore
		manager KeyManager
	}
	type args struct {
		criteria *model.KeyFilterCriteria
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*model.KeyResponse
		wantErr bool
	}{
		{
			name: "Validate search key with valid input, should search for a key",
			fields: fields{
				store:   keyStore,
				manager: keyManager,
			},
			args: args{
				criteria: &model.KeyFilterCriteria{
					Algorithm:        "AES",
					KeyLength:        256,
					TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:   tt.fields.store,
				manager: tt.fields.manager,
			}
			_, err := rm.SearchKeys(tt.args.criteria)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.SearchKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRemoteManagerRegisterKey(t *testing.T) {

	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	keyManager := NewKmipManager(mockClient)

	keyStore = mocks.NewFakeKeyStore()

	type fields struct {
		store   repository.KeyStore
		manager KeyManager
	}
	type args struct {
		request *model.KeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *model.KeyResponse
		wantErr bool
	}{
		{
			name: "Validate register key with valid input, should register a key",
			fields: fields{
				store:   keyStore,
				manager: keyManager,
			},
			args: args{
				request: &model.KeyRequest{
					KeyInfo: &model.KeyInfo{
						Algorithm: "AES",
						KeyLength: 256,
						KmipKeyID: "1",
					},
					TransferPolicyID: uuid.MustParse("3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9"),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:   tt.fields.store,
				manager: tt.fields.manager,
			}
			_, err := rm.RegisterKey(tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.RegisterKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRemoteManagerTransferKey(t *testing.T) {

	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	keyStore = mocks.NewFakeKeyStore()

	type fields struct {
		store   repository.KeyStore
		manager KeyManager
	}
	type args struct {
		keyId uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Validate transfer key with valid input, should transfer a key",
			fields: fields{
				store:   keyStore,
				manager: keyManager,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:   tt.fields.store,
				manager: tt.fields.manager,
			}
			_, err := rm.TransferKey(tt.args.keyId)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.TransferKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewRemoteManager(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	keyManager := NewKmipManager(mockClient)

	keyStore = mocks.NewFakeKeyStore()

	type args struct {
		ks  repository.KeyStore
		km  KeyManager
		url string
	}
	tests := []struct {
		name string
		args args
		want *RemoteManager
	}{
		{
			name: "Validate passing input to the struct, should fill without any error",
			args: args{
				ks: keyStore,
				km: keyManager,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewRemoteManager(tt.args.ks, tt.args.km)
		})
	}
}
