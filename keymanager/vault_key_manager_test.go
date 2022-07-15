/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"encoding/json"
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/vaultclient"
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
				algorithm:  "AES",
				vaultKeyID: "20ba514a-f698-485d-a033-63ca9984b288",
				keyData:    "urNoe6OU/2dqvYPP40FTVEgIPhIJ9Za4hu9keAwtfC4=",
				keyLength:  256,
			},
			wantErr: false,
		},
		{
			name: "register RSA key",
			args: args{
				algorithm:  "RSA",
				vaultKeyID: "20ba514a-f698-485d-a033-63ca9984b288",
				keyData:    "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDTYB95zrg8Op+5\n/bfX8HCeCXhaxa7m/3chsEXW9EEaY6kz46U+SDDcJ3K7yorLW8mrTAsEPldAzZv8\nMzeg3elZAbAI0EJStd1FM9OFbjKEQJl3yiT8rilF3edUBUwKmxtt+LgM8VQQHwI3\nlHFUK9NWSYd8UuwvEcNCYyU+pKjgmoJ7QqqY20kiJ5/jjsD6AWoUMitFM0t8LD0X\n7sTPJ0Cc1ICFLxCOoDB/+JrX+cLVvx3AeTX8d5MU7fIHoRx/zn9j2ed2Al+6jBnR\nCVkLuPUtvBs4ZZKFyE946a8iTp0bZ2sFzliznN4tA49T1uN8aD7fjWoeugUvXwN7\nXpUw+9UvAgMBAAECggEAbueWXEDcZa2UtO+skD51uFXbsjTaqhUMGr70Re5uYjw8\nQR+GSgFysXB5QJLq8/w6+geyGA3llfjLiS4OV/dXQf4isN0kj2UgrfidWPsSwlVq\nsHF9qp5uxVvCzlDhLwdnAvJnD1Nn+fVrImJee/1qq3F1BwQzLBczzhdbKV0XxpAX\nHWIahXg0zaVQAhzYsEfFOwsrHnZo/JrB9sVHOSpsR5VHdalBRSp2i+pQRWkUmMnJ\nxFP3/FoLR4WBG+ooJxDJLEShEkO+SEVtH/fN2X6UuVa3pMnGu4HzFO5PvO5Wupn8\ntLrgPxVSf8BDO3sjNVW+MmWu6rPGQtTiHEmzTWUZcQKBgQDm8ukzcHn7Ozj2HMk1\n4kMlc40nU2XdUKvNDDr9cPgXWdLgXFN1fod9ePk88/dhdHgtL9wp0rGGzdt6PoCR\nLhvPuobBXlwhbxiKG5oxdT4CERjpxciBtu+gz3XbvIzMxIf8tSv9tV1H+97+U6NP\nC65pO3iQAwlnjQwhc4eWj5VgDQKBgQDqTbCG1wCEyXMcQNyKxYxYpfE/9856C18Y\nYNFhNLBkyoGzIxcVXUl+yonij4eN9gIdcRvRF9D61H1MIhWKSFrovbIL2ZUs8rIS\nunmULygpLWCz9ddsGkIRWEci9Y/gQ7B9FI6atPL/K/w80N02x7R2erQiEU58JHeB\nOTNrJ2e/KwKBgCgewMZP3tD3G9EddRLoSJPj+/x9729ACWhonILUsjSURR72ywTZ\nQz5X2qxtEWebrRjkfJHDaVWqw1r8KqeN5AT1OV20P7sLKq8rVmELJgeD4tkRo+Bs\n4DoGcEoI+kjER39uFcNQU3Ei3z09WFxuAhGD5FDYRjT3+siA4mgUb3WtAoGAEaWY\nTg+TcmzZxp77/VezolmdOfwoCPkiSGvCWVfmkTDPY/aYnntQNcR7bhzxULfeoOkL\n90ub6chnR3ypsqiQcEcZSdsxaRk+YDq7PXXvyGoqhmNVvkacA0Jq2S81juaKPGF3\n/B70zlM5xDrW7nFMHkBPoOE80AzPE2SDguaM4dECgYEAykeY3MuWHt3wc4VbRta5\nM+apHzWeb/WqihTEDp4PqB0F8RhNXppwzJfDCMxrxwmgY05v4yEQwTNtIIRviG96\nW/7ilH1sYmSz3v2RsWaMDG5gjK061GMWQr0KD3Q9QOOJxelGjvR0P1SHWp7M8/aQ\nqlRhF5/3Tah5hazgCNKjNlI=\n-----END RSA PRIVATE KEY-----",
				keyLength:  256,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyInfo := &model.KeyInfo{
				Algorithm: tt.args.algorithm,
				KmipKeyID: tt.args.vaultKeyID,
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
