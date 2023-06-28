/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
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

type Nonce struct {
	Val       []byte `json:"val"`
	Iat       []byte `json:"iat"`
	Signature []byte `json:"signature"`
}

// GetNonce sends a GET request to Appraisal Service to create a new Nonce to be used as reportdata for quote generation
func (ac *asClient) GetNonce() (*Nonce, error) {

	newRequest := func() (*http.Request, error) {
		url := fmt.Sprintf("%s/nonce", ac.BaseURL)
		return http.NewRequest(http.MethodGet, url, nil)
	}

	var queryParams map[string]string = nil
	var headers = map[string]string{
		constant.HTTPHeaderTypeXApiKey: ac.ApiKey,
		constant.HTTPHeaderKeyAccept:   constant.HTTPHeaderValueApplicationJson,
	}

	var Nonce Nonce
	processResponse := func(resp *http.Response) error {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if err = json.Unmarshal(body, &Nonce); err != nil {
			return err
		}
		return nil
	}

	if err := clients.RequestAndProcessResponse(ac.Client, newRequest, queryParams, headers, processResponse); err != nil {
		return nil, err
	}

	return &Nonce, nil
}
