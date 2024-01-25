/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package vaultclient

import (
	"encoding/json"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	constants "intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"net/url"
)

type VaultClient interface {
	InitializeClient(string, string, string) error
	CreateKey(*model.KeyAttributes) error
	DeleteKey(string) error
	GetKey(string) ([]byte, error)
	ListKeys() ([]interface{}, error)
}

type vaultClient struct {
	c *(api.Logical)
}

func NewVaultClient() VaultClient {
	return &vaultClient{}
}

func (vc *vaultClient) InitializeClient(serverIP string, serverPort string, clientToken string) error {
	serverURL := url.URL{
		Scheme: "http",
		Host:   serverIP + ":" + serverPort,
	}
	// vaultAddr := "http://" + serverIP + ":" + serverPort
	vaultAddr := serverURL.String()
	config := &api.Config{
		Address: vaultAddr,
	}

	client, err := api.NewClient(config)
	if err != nil {
		return errors.New("vaultclient/vaultclient:InitializeClient() Failed to initiaize vault client.")
	}
	client.SetToken(clientToken)

	log.Info("vaultclient/vaultclient:InitializeClient() Vault client initialized")
	vc.c = client.Logical()
	return nil
}

func (vc *vaultClient) CreateKey(keyAttrib *model.KeyAttributes) error {
	id := keyAttrib.ID

	jsonKey, err := json.Marshal(keyAttrib)
	if err != nil {
		log.Errorf("Error while marshalling key attributes: %s", err.Error())
		return err
	}

	_, err = vc.c.Write(constants.VAULT_KEY_ROOT_PATH+id.String(),
		map[string]interface{}{
			id.String(): string(jsonKey),
		})
	if err != nil {
		return err
	}
	return nil

}

func (vc *vaultClient) DeleteKey(keyID string) error {
	_, err := vc.c.Delete(constants.VAULT_KEY_ROOT_PATH + keyID)
	if err != nil {
		return errors.Wrapf(err, "Failed to delete key %s from vault server", keyID)
	}
	log.Infof("vaultclient/vaultclient:DeleteKey() Deleted key %s from vault server", keyID)
	return nil
}

func (vc *vaultClient) GetKey(keyID string) ([]byte, error) {
	secret, err := vc.c.Read(constants.VAULT_KEY_ROOT_PATH + keyID)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to retrieve key from vault server.")
	} else if secret == nil {
		return nil, errors.Errorf("Failed to retrieve the key from vault. key with ID %s is not found", keyID)
	}
	log.Info("vaultclient/vaultclient:GetKey() Retrieved key from vault server")

	data := secret.Data[keyID]
	keyInfo := data.(string)
	val := []byte(keyInfo)
	return val, nil
}

func (vc *vaultClient) ListKeys() ([]interface{}, error) {
	keyMap, err := vc.c.List(constants.VAULT_KEY_ROOT_PATH)
	if err != nil {
		return nil, err
	}

	listOfKeys := keyMap.Data["keys"].([]interface{})

	return listOfKeys, nil
}
