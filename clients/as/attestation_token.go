/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package as

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"intel/amber/kbs/v1/clients"
	"intel/amber/kbs/v1/clients/constant"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type AttestationTokenRequest struct {
	Quote         []byte         `json:"quote"`
	VerifierNonce *VerifierNonce `json:"verifier_nonce,omitempty"`
	RuntimeData   []byte         `json:"runtime_data,omitempty"`
	PolicyIds     []uuid.UUID    `json:"policy_ids,omitempty"`
	EventLog      []byte         `json:"event_log,omitempty"`
}

type AttestationTokenResponse struct {
	Token string `json:"token"`
}

// GetAttestationToken sends a POST request to Appraisal Service to create a new Attestation token with the specified quote attributes
func (ac *asClient) GetAttestationToken(tokenRequest *AttestationTokenRequest) (string, error) {

	newRequest := func() (*http.Request, error) {
		url := fmt.Sprintf("%s/attest", ac.BaseURL)

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
		constant.HTTPHeaderKeyAccept:      constant.HTTPHeaderValueApplicationJson,
	}

	var tokenResponse AttestationTokenResponse
	processResponse := func(resp *http.Response) error {
		attestationToken, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = json.Unmarshal(attestationToken, &tokenResponse)
		if err != nil {
			return errors.Wrap(err, "Error unmarshalling Token response from appraise")
		}
		return nil
	}

	if err := clients.RequestAndProcessResponse(ac.Client, newRequest, queryParams, headers, processResponse); err != nil {
		return "", err
	}

	return tokenResponse.Token, nil
}
