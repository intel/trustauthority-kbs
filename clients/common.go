/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package clients

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"intel/amber/kbs/v1/crypt"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func HTTPClientTLSNoVerify() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func HTTPClientWithCA(caCertificates []x509.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: crypt.GetCertPool(caCertificates),
			},
		},
	}
}

func RequestAndProcessResponse(
	client *http.Client,
	newRequest func() (*http.Request, error),
	queryParams map[string]string,
	headers map[string]string,
	processResponse func(*http.Response) error,
) error {
	var req *http.Request
	var err error

	if req, err = newRequest(); err != nil {
		return err
	}

	{
		if queryParams != nil {
			q := req.URL.Query()
			for param, val := range queryParams {
				q.Add(param, val)
			}
			req.URL.RawQuery = q.Encode()
		}
	}

	{
		if headers != nil {
			for name, val := range headers {
				req.Header.Add(name, val)
			}
		}
	}

	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return err
	}

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				log.WithError(err).Errorf("Failed to close response body")
			}
		}()
	}

	if resp.StatusCode != http.StatusOK || resp.ContentLength == 0 {
		return errors.Errorf("Invalid response: StatusCode = %d, ContentLength = %d", resp.StatusCode, resp.ContentLength)
	}

	return processResponse(resp)
}
