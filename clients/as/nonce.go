/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package as

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"intel/amber/kbs/v1/clients"
	"intel/amber/kbs/v1/clients/constant"
)

type SignedNonce struct {
	Nonce     []byte `json:"nonce"`
	Signature []byte `json:"signature"`
}

// GetNonce sends a GET request to Appraisal Service to create a new Nonce to be used as userdata for quote generation
func (ac *asClient) GetNonce() (*SignedNonce, error) {

	newRequest := func() (*http.Request, error) {
		url := fmt.Sprintf("%s/nonce", ac.BaseURL)
		return http.NewRequest(http.MethodGet, url, nil)
	}

	var queryParams map[string]string = nil
	var headers = map[string]string{
		constant.HTTPHeaderTypeXApiKey: ac.ApiKey,
		constant.HTTPHeaderKeyAccept:   constant.HTTPHeaderValueApplicationJson,
	}

	var signedNonce SignedNonce
	processResponse := func(resp *http.Response) error {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if err = json.Unmarshal(body, &signedNonce); err != nil {
			return err
		}
		return nil
	}

	if err := clients.RequestAndProcessResponse(ac.Client, newRequest, queryParams, headers, processResponse); err != nil {
		return nil, err
	}

	return &signedNonce, nil
}
