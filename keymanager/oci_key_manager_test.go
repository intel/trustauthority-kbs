/*
 *   Copyright (c) 2025 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"intel/kbs/v1/model"
	"intel/kbs/v1/ociclient"
	"testing"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

func TestOciManagerCreateKey(t *testing.T) {

	type args struct {
		compartmentId string
		keyId         string
		secretName    string
		vaultId       string
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		wantFail bool
	}{
		{
			name: "Create key",
			args: args{
				compartmentId: "ocid1.compartment.oc1",
				keyId:         "ocid1.key.oc1",
				secretName:    "oci.secret.name",
				vaultId:       "ocid1.vault.oc1",
			},
			wantErr:  false,
			wantFail: false,
		},
		{
			name: "negative test - Create key",
			args: args{
				compartmentId: "ocid1.compartment.oc1",
				keyId:         "ocid1.key.oc1",
				secretName:    "oci.secret.name",
				vaultId:       "ocid1.vault.oc1",
			},
			wantErr:  true,
			wantFail: true,
		},
		{
			name: "negative test - Missing compartment ID",
			args: args{
				compartmentId: "",
				keyId:         "ocid1.key.oc1",
				secretName:    "oci.secret.name",
				vaultId:       "ocid1.vault.oc1",
			},
			wantErr:  true,
			wantFail: false,
		},
		{
			name: "negative test - Missing key ID",
			args: args{
				compartmentId: "ocid1.compartment.oc1",
				keyId:         "",
				secretName:    "oci.secret.name",
				vaultId:       "ocid1.vault.oc1",
			},
			wantErr:  true,
			wantFail: false,
		},
		{
			name: "negative test - Missing secret name",
			args: args{
				compartmentId: "ocid1.compartment.oc1",
				keyId:         "ocid1.key.oc1",
				secretName:    "",
				vaultId:       "ocid1.vault.oc1",
			},
			wantErr:  true,
			wantFail: false,
		},
		{
			name: "negative test - Missing vault ID",
			args: args{
				compartmentId: "ocid1.compartment.oc1",
				keyId:         "ocid1.key.oc1",
				secretName:    "oci.secret.name",
				vaultId:       "",
			},
			wantErr:  true,
			wantFail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			uuid, err := uuid.NewRandom()
			if err != nil {
				t.Errorf("CreateKey() error generating uuid = %v", err)
				return
			}

			keyInfo := &model.KeyInfo{
				Algorithm: "AES",
				KeyLength: 256,
			}

			ociInfo := &model.OciInfo{
				CompartmentId: tt.args.compartmentId,
				KeyId:         tt.args.keyId,
				SecretName:    tt.args.secretName,
				VaultId:       tt.args.vaultId,
			}

			keyRequest := &model.KeyRequest{
				TransferPolicyID: uuid,
				KeyInfo:          keyInfo,
				OciInfo:          ociInfo,
			}

			mockClient := ociclient.NewMockOCIClient()
			if tt.wantFail {
				mockClient.On("CreateKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", errors.New("failed to create key"))
			} else {
				mockClient.On("CreateKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil)
			}
			keyManager := &OCIManager{mockClient}
			_, err = keyManager.CreateKey(keyRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestOciManagerDeleteKey(t *testing.T) {

	type args struct {
		secretID string
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		wantFail bool
	}{
		{
			name: "Delete key",
			args: args{
				secretID: "20ba514a-f698-485d-a033-63ca9984b288",
			},
			wantErr:  false,
			wantFail: false,
		},
		{
			name: "negative test - Delete key",
			args: args{
				secretID: "20ba514a-f698-485d-a033-63ca9984b288",
			},
			wantErr:  true,
			wantFail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ociAttributes := &model.OciAttributes{
				SecretId: tt.args.secretID,
			}

			keyAttributes := &model.KeyAttributes{
				Oci: ociAttributes,
			}

			mockClient := ociclient.NewMockOCIClient()
			if tt.wantFail {
				mockClient.On("DeleteKey", mock.Anything).Return(errors.New("failed to delete key"))
			} else {
				mockClient.On("DeleteKey", mock.Anything).Return(nil)
			}
			keyManager := &OCIManager{mockClient}
			err := keyManager.DeleteKey(keyAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestOciManagerRegisterKey(t *testing.T) {

	type args struct {
		secretID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Register key",
			args: args{
				secretID: "20ba514a-f698-485d-a033-63ca9984b288",
			},
			wantErr: false,
		},
		{
			name: "negative test - Register key",
			args: args{
				secretID: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			uuid, err := uuid.NewRandom()
			if err != nil {
				t.Errorf("RegisterKey() error generating uuid = %v", err)
				return
			}

			keyInfo := &model.KeyInfo{
				Algorithm: "AES",
				KeyLength: 256,
			}

			ociInfo := &model.OciInfo{
				SecretId: tt.args.secretID,
			}

			keyRequest := &model.KeyRequest{
				TransferPolicyID: uuid,
				KeyInfo:          keyInfo,
				OciInfo:          ociInfo,
			}

			mockClient := ociclient.NewMockOCIClient()
			keyManager := &OCIManager{mockClient}
			_, err = keyManager.RegisterKey(keyRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestOciManagerTransferKey(t *testing.T) {

	type args struct {
		secretID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Transfer key",
			args: args{
				secretID: "20ba514a-f698-485d-a033-63ca9984b288",
			},
			wantErr: false,
		},
		{
			name: "negative test - Transfer key",
			args: args{
				secretID: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ociAttributes := &model.OciAttributes{
				SecretId: tt.args.secretID,
			}

			keyAttributes := &model.KeyAttributes{
				Oci: ociAttributes,
			}

			key := []byte{0}
			mockClient := ociclient.NewMockOCIClient()
			mockClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
			keyManager := &OCIManager{mockClient}
			_, err := keyManager.TransferKey(keyAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransferKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
