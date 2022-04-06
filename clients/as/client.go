/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package as

import (
	"net/http"
	"net/url"
)

type ASClient interface {
	GetAttestationToken(*AttestationTokenRequest) ([]byte, error)
	GetNonce() (*SignedNonce, error)
}

type asClient struct {
	Client  *http.Client
	BaseURL *url.URL
	ApiKey  string
}

func NewASClient(client *http.Client, baseURL *url.URL, apiKey string) ASClient {
	return &asClient{
		Client:  client,
		BaseURL: baseURL,
		ApiKey:  apiKey,
	}
}
