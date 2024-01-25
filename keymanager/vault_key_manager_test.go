/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"encoding/json"
	"github.com/stretchr/testify/mock"
	"intel/kbs/v1/model"
	"intel/kbs/v1/vaultclient"
	"testing"
)

func TestVaultManagerCreateKey(t *testing.T) {

	type args struct {
		algorithm string
		curveType string
		keyLength int
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
			},
			wantErr: false,
		},
		{
			name: "create asymmetric key",
			args: args{
				algorithm: "RSA",
				keyLength: 2048,
			},
			wantErr: false,
		},
		{
			name: "negative test - algorithm not supported",
			args: args{
				algorithm: "ECBBBB",
				keyLength: 2048,
			},
			wantErr: true,
		},
		{
			name: "negative test - Curve type not supported",
			args: args{
				algorithm: "EC",
				curveType: "primeinvalid",
			},
			wantErr: true,
		},
		{
			name: "Supported curve type",
			args: args{
				algorithm: "EC",
				curveType: "secp521r1",
			},
			wantErr: false,
		},
		{
			name: "Supported curve type prime256",
			args: args{
				algorithm: "EC",
				curveType: "prime256v1",
			},
			wantErr: false,
		},
		{
			name: "Supported curve type secp384",
			args: args{
				algorithm: "EC",
				curveType: "secp384r1",
			},
			wantErr: false,
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

			mockClient := vaultclient.NewMockVaultClient()
			mockClient.On("CreateKey", mock.Anything).Return(nil)
			keyManager := &VaultManager{mockClient}
			_, err := keyManager.CreateKey(keyRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestVaultManagerDeleteKey(t *testing.T) {

	type args struct {
		vaultKeyID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "delete key",
			args: args{
				vaultKeyID: "20ba514a-f698-485d-a033-63ca9984b288",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyAttributes := &model.KeyAttributes{
				KmipKeyID: tt.args.vaultKeyID,
			}
			mockClient := vaultclient.NewMockVaultClient()
			mockClient.On("DeleteKey", mock.Anything).Return(nil)
			keyManager := &VaultManager{mockClient}
			err := keyManager.DeleteKey(keyAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestVaultManagerRegisterKey(t *testing.T) {

	type args struct {
		algorithm  string
		vaultKeyID string
		keyData    string
		keyLength  int
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
				keyData:   "urNoe6OU/2dqvYPP40FTVEgIPhIJ9Za4hu9keAwtfC4=",
				keyLength: 256,
			},
			wantErr: false,
		},
		{
			name: "register RSA key",
			args: args{
				algorithm: "RSA",
				keyData:   "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQzZlRVhwZHpzZkRuaUkKTmtQTXJ5WGdlMkJtUXFiT1JEYUdvend4azR5aHJMalZmbUFDUk1GaVZ2ZzZLcm9RbGNWOTByN0FtdHhYWjBDcwp0VEN5YXlVVDltV3pEYldSck9FKzFRSXpGNEZYTStmOWhGM3dmR1BFamk0K2dEUUdXSTdlcXUvTVluc3VGOE8zCk9iTzRoOG5oMFc5ZUF6VjIzaDRzd2crMUk3Zzl3ZlE1blhDUUVxVVd1U2ZTZVdwZE00Y2U5K0hSbm1QTjFudXMKdWNvUmZjVzdNVFFTYmpQS3JWU2YwZ1FUQlZxVml4Q1Z2THdXZXdNZ1hhM1dObE45NE9GMjVhTlZVUG5DRlZFTApydXg4MThQNDVvYmRrT2ZLRXhHUDV4TlU5aDkyOU5Fc0hnYUJ6cERidjZHSzR0SzdwM213ZmtuaHBKK0wrb3pKCnVsUSs4WitwQWdNQkFBRUNnZ0VBQnU5S1pWRjZ6Ry9CWUlwenczWXM1ZEFjMEl6RnhKUnhtb05TQXZqU2EvV3AKd3VuWFl2bzJOQm9EMHdaTUEyb2pMVDB6L00zUzZEbGwyZzV4S2FUVnNtRjhCeTNPalBvcTZkSHFQM3dZMTdBQwozcEVvY2wvdWtNSDdaYlc4U1pOTCtVQzQ3ZWI5M3dQV3ArR2wyd28wd2pqT1hYRm4yM3hNK2J2bXNZL3ErTGxGCnVNc2kxaHZUK2dhUWxoV00yS3BOSEl1SDY0NHhSUFoyN0VPR2c3WCtueGN0Mjh0cUtDSlVmMzFqd0JFVVo2bVUKTFhJd3QrV2FTOGRCQ3dJb1lCSjNlN0VZWGRKRjMwOHFMYW55YTVWbFMwRFZObU5vWGowM3dSMnNSL1M4VW9YWApGREY5UGVlMEo0T2d0MHZnU2lYay8zYTVnaUczMVBKZWR4MmpVdFFBOFFLQmdRRFl0RUkrUVZrakRQYzU0NzRMCkZ2UFBieGpqSHpjT0Nabll3WTJUNTdMS0t1czdYS1Fhbm9sRXlHSFpnaDh2NjhJdzNBdGhYNk5vZk5CZEdMQ3EKa0J3dlJseUJwVXR1bzF2SXp5aXlIcVVGZTBtMjk1SzVYdDIvbUYrMGRxaVlMdTBrMHZSbHo5Z3cxK0JWYWVtYwpXNyt1cnAxZ0dSamFLV3Nra3dNM3FFMHRHUUtCZ1FEY1NIMlBVUFBXUTlaYkRFRVRUWkY5RVV3dnVkR1M5WXhFCjN3VTI2YjRpTDN1bEtxV1N3Z3hzaVRpV0pMK3hJNVV2L0ppaHp5TWFpMDBmZkl6YzBvZEl6U1NQSjlJa3h1dXcKQUZPS092NzJOcUYrZnNlRjlEOWZvVS9QTUhraDROald5SHUvN1lTMEw2MVVTU081a2ErRjIxK0ZzalBNczkzVQpQQlFsNk5ISkVRS0JnUUN6Z0cwMndFNmptQVBaY2VwanFUbC80OWpMbVhtektRVEU1Vjd1MndmZ0tyajdUUHVxCkNSUlBZMlNhRlF6Y1Z2OWVGWWRmdXliU1VFRVFQSGxxYjBESmNCRUVXdlVteWk0bkltSGxXVGo4VjJseUk1VG4KODhyZS84cVc0NHMzcy9jL2YzWnVOMEl2QTBLUnZjK0Njd1ZPSHRuQlZraWR2WjFBaUg0cnhqOVhVUUtCZ0dUYQpWNG9uSVF4SFVMdXN0NXFUMS9sdjB2YkMxMzIyS0R0YjlESTVBQkQ4dGxwZlZTRUU4TlU4V2dqNzJEdk1zOEFkCm9PL3NPd0VySitzemhmYVArTnBPK2Q4RTkwUlpRb3o1Q1VadlRrNEJveHljQk5PQ2lRVktnSlMyZDY4WUY0NzIKaVJuTk1BV2pFbk5WYlNMSDNabW1YMnlCc3crVWhncG1XejhrQWZCUkFvR0Flc1l5Y2wwRS83T0FtZ0dzNU1mUQpRUUpkZ1ROb3pGUGI5bkFMdjI1cGh0VDlMM2FRSXlDK1A2bHBnV295ZlY1VWQ2VGZqaWpqZ3VlQ0hPd1cyTURzClFLTFNpUWRydDRjSnVlVWNCL3JaWG9JR1AzaFRxcVVwVXVuL2lDSG81aW5uMVFxVzkwV3hqYTUwL1lvWE9mYk8KQWdhS1ZoRjl6N3g2dWdPRlRwSGx5aFk9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0=",
				keyLength: 3072,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyInfo := &model.KeyInfo{
				Algorithm: tt.args.algorithm,
				KeyData:   tt.args.keyData,
				KeyLength: tt.args.keyLength,
			}

			keyRequest := &model.KeyRequest{
				KeyInfo: keyInfo,
			}

			mockClient := vaultclient.NewMockVaultClient()
			mockClient.On("CreateKey", mock.Anything).Return(nil)
			keyManager := &VaultManager{mockClient}
			_, err := keyManager.RegisterKey(keyRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestVaultManagerTransferKey(t *testing.T) {

	type args struct {
		algorithm  string
		vaultKeyID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "get symmetric key",
			args: args{
				algorithm:  "AES",
				vaultKeyID: "20ba514a-f698-485d-a033-63ca9984b288",
			},
			wantErr: false,
		},
		{
			name: "get asymmetric key",
			args: args{
				algorithm:  "RSA",
				vaultKeyID: "20ba514a-f698-485d-a033-63ca9984b288",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyAttributes := &model.KeyAttributes{
				Algorithm: tt.args.algorithm,
				KmipKeyID: tt.args.vaultKeyID,
			}

			keyAttr, _ := json.Marshal(keyAttributes)
			mockClient := vaultclient.NewMockVaultClient()
			mockClient.On("GetKey", mock.Anything).Return(keyAttr, nil)
			keyManager := &VaultManager{mockClient}
			_, err := keyManager.TransferKey(keyAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransferKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
