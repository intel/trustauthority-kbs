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

type JWK struct {
	// Key type.
	// required: true
	// example: RSA
	Kty string `json:"kty"`
	// Key identifier.
	// example: tee-pubkey
	Kid string `json:"kid,omitempty"`
	// Public key use.
	// example: enc
	Use string `json:"use,omitempty"`
	// JWE key management algorithm.
	// example: RSA-OAEP-256
	Alg string `json:"alg,omitempty"`

	// RSA modulus (base64url).
	// example: sXch4h0S9aJYpYfH0Ej4w5a5lqC1gJ5cS2C5s8VZ7zU
	N string `json:"n,omitempty"`
	// RSA public exponent (base64url).
	// example: AQAB
	E string `json:"e,omitempty"`

	// EC curve.
	// example: P-256
	Crv string `json:"crv,omitempty"`
	// EC X coordinate (base64url).
	// example: f83OJ3D2xF4X8cG0M4x5HnQOQp2VfQp2G8nVbW8p6lA
	X string `json:"x,omitempty"`
	// EC Y coordinate (base64url).
	// example: x_FEzRu9h0vJfR0N9Y5s3mV9mSzW4JY5C7QkV4d1P8E
	Y string `json:"y,omitempty"`
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
		case "P-256", "P-521":
			return nil
		default:
			return errors.Errorf("unsupported ec curve %q", k.Crv)
		}
	}

	return errors.Errorf("unsupported jwk kty %q", k.Kty)
}

type Tee string

const (
	TeeSGX Tee = "sgx"
	TeeTDX Tee = "tdx"
)

type RCARAuthRequest struct {
	// RCAR protocol version.
	// required: true
	// example: 0.4.0
	Version string `json:"version"`
	// Requested TEE type.
	// required: true
	// example: tdx
	TEE Tee `json:"tee"`
	// Optional protocol extensions.
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

type RCARChallenge struct {
	// Server nonce that must be echoed in runtime-data.nonce.
	// required: true
	// example: A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6
	Nonce string `json:"nonce"`
	// Extra parameters chosen by server for this session.
	ExtraParams map[string]interface{} `json:"extra-params"`
}

type RuntimeData struct {
	// Nonce returned by /kbs/v0/auth.
	// required: true
	// example: A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6
	Nonce string `json:"nonce"`
	// Workload public key used to encrypt returned resource.
	// required: true
	TEEPubKey JWK `json:"tee-pubkey"`
}

type CompositeEvidence struct {
	// Primary TEE evidence blob.
	// required: true
	PrimaryEvidence json.RawMessage `json:"primary_evidence"`
	// Optional additional evidence for secondary devices.
	AdditionalEvidence string `json:"additional_evidence,omitempty"`
}

type InitData struct {
	// Format of init data payload.
	// example: json
	Format string `json:"format,omitempty"`
	// Plaintext init data body.
	Body string `json:"body,omitempty"`
}

type RCARAttestationRequest struct {
	// Optional initialization data.
	InitData *InitData `json:"init-data,omitempty"`
	// Runtime nonce and public key.
	// required: true
	RuntimeData RuntimeData `json:"runtime-data"`
	// Attestation evidence bundle.
	// required: true
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

type RCARAttestationResponse struct {
	// Attestation token for subsequent resource retrieval.
	// required: true
	Token string `json:"token"`
}

type ProblemDetails struct {
	// Problem type URI.
	// example: about:blank
	Type string `json:"type,omitempty"`
	// Short human-readable summary.
	// required: true
	// example: Unauthorized
	Title string `json:"title"`
	// HTTP status code.
	// required: true
	// example: 401
	Status int `json:"status"`
	// Detailed problem message.
	// example: unsupported protocol version
	Detail string `json:"detail,omitempty"`
	// URI reference that identifies the specific occurrence.
	Instance string `json:"instance,omitempty"`
}

const (
	ProblemTypeAboutBlank = "about:blank"
)

type ResourceAddress struct {
	// Resource repository segment.
	// example: default
	Repository string
	// Resource type segment.
	// example: key
	Type string
	// Resource tag segment.
	// example: 7110194b-a703-4657-9d7f-3e02b62f2ed8
	Tag string
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
