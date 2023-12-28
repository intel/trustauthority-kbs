/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package ita

import (
	"crypto/tls"
	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
	"intel/kbs/v1/config"
)

func NewITAClient(config *config.Configuration, serverNameTlsConfig string) (itaConnector.Connector, error) {

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverNameTlsConfig,
	}

	cfg := itaConnector.Config{
		BaseUrl:     config.TrustAuthorityBaseUrl,
		TlsCfg:      tlsConfig,
		ApiUrl:      config.TrustAuthorityApiUrl,
		ApiKey:      config.TrustAuthorityApiKey,
		RetryConfig: nil,
	}

	connector, err := itaConnector.New(&cfg)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating an instance of TrustAuthority Client")
	}
	return connector, nil
}
