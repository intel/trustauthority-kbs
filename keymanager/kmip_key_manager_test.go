/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"intel/kbs/v1/kmipclient"
	"intel/kbs/v1/model"
)

func TestKmipManagerCreateKey(t *testing.T) {

	type args struct {
		algorithm string
		curveType string
		keyLength int
		funcName  string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "create symmetric key",
			args: args{
				algorithm: "AES",
				keyLength: 256,
				funcName:  "CreateSymmetricKey",
			},
			wantErr: false,
		},
		{
			name: "create asymmetric key",
			args: args{
				algorithm: "RSA",
				keyLength: 2048,
				funcName:  "CreateAsymmetricKeyPair",
			},
			wantErr: false,
		},
		{
			name: "negative test - algorithm not supported",
			args: args{
				algorithm: "ECBBBB",
				keyLength: 2048,
				funcName:  "CreateAsymmetricKeyPair",
			},
			wantErr: true,
		},
		{
			name: "negative test - Curve type not supported",
			args: args{
				algorithm: "EC",
				curveType: "primeinvalid",
				funcName:  "CreateAsymmetricKeyPair",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyInfo := &model.KeyInfo{
				Algorithm: tt.args.algorithm,
				KeyLength: tt.args.keyLength,
				CurveType: tt.args.curveType,
			}

			keyRequest := &model.KeyRequest{
				KeyInfo: keyInfo,
			}

			mockClient := kmipclient.NewMockKmipClient()
			mockClient.On(tt.args.funcName, mock.Anything).Return("1", nil)
			keyManager := &KmipManager{mockClient}
			_, err := keyManager.CreateKey(keyRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKmipManagerDeleteKey(t *testing.T) {

	type args struct {
		kmipKeyID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "delete key",
			args: args{
				kmipKeyID: "1",
			},
			wantErr: false,
		},
		{
			name: "negative test - key id is empty",
			args: args{
				kmipKeyID: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyAttributes := &model.KeyAttributes{
				KmipKeyID: tt.args.kmipKeyID,
			}
			mockClient := kmipclient.NewMockKmipClient()
			mockClient.On("DeleteKey", mock.Anything).Return(nil)
			keyManager := &KmipManager{mockClient}
			err := keyManager.DeleteKey(keyAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKmipManagerRegisterKey(t *testing.T) {

	type args struct {
		algorithm string
		kmipKeyID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "register key",
			args: args{
				algorithm: "AES",
				kmipKeyID: "1",
			},
			wantErr: false,
		},
		{
			name: "negative testing - kmipKeyID is empty",
			args: args{
				algorithm: "AES",
				kmipKeyID: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyInfo := &model.KeyInfo{
				Algorithm: tt.args.algorithm,
				KmipKeyID: tt.args.kmipKeyID,
			}

			keyRequest := &model.KeyRequest{
				KeyInfo: keyInfo,
			}

			mockClient := kmipclient.NewMockKmipClient()
			keyManager := &KmipManager{mockClient}
			_, err := keyManager.RegisterKey(keyRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKmipManagerTransferKey(t *testing.T) {

	type args struct {
		algorithm string
		kmipKeyID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "get symmetric key",
			args: args{
				algorithm: "AES",
				kmipKeyID: "1",
			},
			wantErr: false,
		},
		{
			name: "get asymmetric key",
			args: args{
				algorithm: "RSA",
				kmipKeyID: "2",
			},
			wantErr: false,
		},
		{
			name: "negative testing - algorithm not supported",
			args: args{
				algorithm: "ECB",
				kmipKeyID: "1",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyAttributes := &model.KeyAttributes{
				Algorithm: tt.args.algorithm,
				KmipKeyID: tt.args.kmipKeyID,
			}

			mockClient := kmipclient.NewMockKmipClient()
			mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
			keyManager := &KmipManager{mockClient}
			_, err := keyManager.TransferKey(keyAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransferKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
