/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package as

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"intel/amber/kbs/v1/clients"
	"intel/amber/kbs/v1/clients/constant"

	"github.com/google/uuid"
)

type AttestationTokenRequest struct {
	Quote     []byte      `json:"quote"`
	Nonce     *Nonce      `json:"nonce,omitempty"`
	UserData  []byte      `json:"user_data,omitempty"`
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
	EventLog  []byte      `json:"event_log,omitempty"`
}

// GetAttestationToken sends a POST request to Appraisal Service to create a new Attestation token with the specified quote attributes
func (ac *asClient) GetAttestationToken(tokenRequest *AttestationTokenRequest) ([]byte, error) {

	newRequest := func() (*http.Request, error) {
		url := fmt.Sprintf("%s/appraise", ac.BaseURL)

		reqBytes, err := json.Marshal(tokenRequest)
		if err != nil {
			return nil, err
		}

		return http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBytes))
	}

	var queryParams map[string]string = nil
	var headers = map[string]string{
		constant.HTTPHeaderTypeXApiKey:    ac.ApiKey,
		constant.HTTPHeaderKeyContentType: constant.HTTPHeaderValueApplicationJson,
		constant.HTTPHeaderKeyAccept:      constant.HTTPHeaderValueApplicationJwt,
	}

	var attestationToken []byte
	processResponse := func(resp *http.Response) error {
		var err error
		if attestationToken, err = ioutil.ReadAll(resp.Body); err != nil {
			return err
		}
		return nil
	}

	if err := clients.RequestAndProcessResponse(ac.Client, newRequest, queryParams, headers, processResponse); err != nil {
		return nil, err
	}

	return attestationToken, nil
}
