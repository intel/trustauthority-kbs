/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
)

// JWK represents the subset of JSON Web Key fields needed by RCAR clients.
// For this service scope, key types are limited to RSA and EC.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`

	// RSA members
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC members
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func (k JWK) IsRSA() bool {
	return strings.EqualFold(k.Kty, "RSA")
}

func (k JWK) IsEC() bool {
	return strings.EqualFold(k.Kty, "EC")
}

func (k JWK) Validate() error {
	if k.IsRSA() {
		if k.N == "" || k.E == "" {
			return errors.New("invalid rsa jwk: both n and e are required")
		}
		return nil
	}

	if k.IsEC() {
		if k.Crv == "" || k.X == "" || k.Y == "" {
			return errors.New("invalid ec jwk: crv, x and y are required")
		}
		switch k.Crv {
		case "P-256", "P-384":
			return nil
		default:
			return errors.Errorf("unsupported ec curve %q", k.Crv)
		}
	}

	return errors.Errorf("unsupported jwk kty %q", k.Kty)
}

// Tee represents the TEE type (SGX, TDX, etc.)
type Tee string

const (
	TeeSGX Tee = "sgx"
	TeeTDX Tee = "tdx"
)

// RCARAuthRequest is the request body for POST /kbs/v0/auth.
// Matches Trustee canonical Request structure.
type RCARAuthRequest struct {
	Version     string                 `json:"version"`
	TEE         Tee                    `json:"tee"`
	ExtraParams map[string]interface{} `json:"extra-params,omitempty"`
}

func (r *RCARAuthRequest) UnmarshalJSON(data []byte) error {
	type alias RCARAuthRequest
	var v alias

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return err
	}

	*r = RCARAuthRequest(v)
	return nil
}

func (r *RCARAuthRequest) Validate() error {
	if r == nil {
		return errors.New("request cannot be nil")
	}

	if r.Version == "" {
		return errors.New("version is required")
	}

	if r.TEE != TeeSGX && r.TEE != TeeTDX {
		return errors.Errorf("unsupported tee %q", r.TEE)
	}

	return nil
}

// RCARChallenge is returned by POST /kbs/v0/auth.
// Matches Trustee canonical Challenge structure.
type RCARChallenge struct {
	Nonce       string                 `json:"nonce"`
	ExtraParams map[string]interface{} `json:"extra-params"`
}

// RuntimeData is part of the Attestation request.
type RuntimeData struct {
	Nonce     string `json:"nonce"`
	TEEPubKey JWK    `json:"tee-pubkey"`
}

// CompositeEvidence contains TEE evidence following Trustee canonical structure.
// Primary evidence is required; additional evidence contains secondary device attestations.
type CompositeEvidence struct {
	PrimaryEvidence    json.RawMessage `json:"primary_evidence"`              // Required: Primary TEE evidence
	AdditionalEvidence string          `json:"additional_evidence,omitempty"` // Optional: JSON string of HashMap<Tee, TeeEvidence>
}

// InitData optionally contains initialization data for attestation.
// Matches Trustee canonical InitData structure with format and body fields.
type InitData struct {
	Format string `json:"format,omitempty"` // Format of init data ("json", "toml", etc.)
	Body   string `json:"body,omitempty"`   // Plaintext of init data
}

// RCARAttestationRequest is the request body for POST /kbs/v0/attest.
// Matches Trustee canonical Attestation structure.
type RCARAttestationRequest struct {
	InitData    *InitData         `json:"init-data,omitempty"`
	RuntimeData RuntimeData       `json:"runtime-data"`
	TEEEvidence CompositeEvidence `json:"tee-evidence"`
}

func (r *RCARAttestationRequest) UnmarshalJSON(data []byte) error {
	type alias RCARAttestationRequest
	var v alias

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return err
	}

	*r = RCARAttestationRequest(v)
	return nil
}

func (r *RCARAttestationRequest) Validate() error {
	if r == nil {
		return errors.New("request cannot be nil")
	}

	if r.RuntimeData.Nonce == "" {
		return errors.New("runtime-data.nonce is required")
	}

	if err := r.RuntimeData.TEEPubKey.Validate(); err != nil {
		return errors.Wrap(err, "invalid runtime-data.tee-pubkey")
	}

	if len(r.TEEEvidence.PrimaryEvidence) == 0 {
		return errors.New("tee-evidence.primary_evidence is required")
	}

	return nil
}

// RCARAttestationResponse is the response body for POST /kbs/v0/attest.
type RCARAttestationResponse struct {
	Token string `json:"token"`
}

// ProblemDetails is an RFC 7807-compatible error document.
type ProblemDetails struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

const (
	ProblemTypeAboutBlank = "about:blank"
)

// ResourceAddress identifies a RCAR resource: /resource/{repository}/{type}/{tag}.
type ResourceAddress struct {
	Repository string
	Type       string
	Tag        string
}

func ParseResourceAddress(repository, resourceType, tag string) (*ResourceAddress, error) {
	if strings.TrimSpace(repository) == "" {
		return nil, errors.New("resource repository is required")
	}
	if strings.TrimSpace(resourceType) == "" {
		return nil, errors.New("resource type is required")
	}
	if strings.TrimSpace(tag) == "" {
		return nil, errors.New("resource tag is required")
	}
	if strings.Contains(repository, "/") || strings.Contains(resourceType, "/") || strings.Contains(tag, "/") {
		return nil, errors.New("resource address segments cannot contain '/'")
	}

	return &ResourceAddress{
		Repository: repository,
		Type:       resourceType,
		Tag:        tag,
	}, nil
}
