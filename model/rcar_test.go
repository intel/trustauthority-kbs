/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"encoding/json"
	"testing"

	"github.com/onsi/gomega"
)

func TestJWKValidate_RSA(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	k := JWK{Kty: "RSA", N: "modulus", E: "AQAB"}
	err := k.Validate()

	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestJWKValidate_RSA_MissingMembers(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	k := JWK{Kty: "RSA", N: "modulus"}
	err := k.Validate()

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("n and e"))
}

func TestJWKValidate_EC_UnsupportedCurve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	k := JWK{Kty: "EC", Crv: "P-521", X: "x", Y: "y"}
	err := k.Validate()

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("unsupported ec curve"))
}

func TestRCARAuthRequestUnmarshalJSON_RejectsUnknownField(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	data := []byte(`{"version":"0.4.0","tee":"sgx","unknown":"field"}`)
	var req RCARAuthRequest
	err := json.Unmarshal(data, &req)

	g.Expect(err).To(gomega.HaveOccurred())
}

func TestRCARAuthRequestValidate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	req := &RCARAuthRequest{Version: "0.4.0", TEE: TeeSGX}
	err := req.Validate()

	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestRCARAuthRequestValidate_MissingVersion(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	req := &RCARAuthRequest{TEE: TeeSGX}
	err := req.Validate()

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("version"))
}

func TestRCARAuthRequestValidate_UnsupportedTEE(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	req := &RCARAuthRequest{Version: "0.4.0", TEE: "unsupported"}
	err := req.Validate()

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("unsupported tee"))
}

func TestRCARAttestationRequestValidate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	req := &RCARAttestationRequest{
		RuntimeData: RuntimeData{
			Nonce:     "test-nonce",
			TEEPubKey: JWK{Kty: "RSA", N: "abc", E: "AQAB"},
		},
		TEEEvidence: CompositeEvidence{
			PrimaryEvidence: []byte(`{"quote":"test"}`),
		},
	}
	err := req.Validate()

	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestRCARAttestationRequestValidate_MissingNonce(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	req := &RCARAttestationRequest{
		RuntimeData: RuntimeData{
			TEEPubKey: JWK{Kty: "RSA", N: "abc", E: "AQAB"},
		},
		TEEEvidence: CompositeEvidence{
			PrimaryEvidence: []byte(`{"quote":"test"}`),
		},
	}
	err := req.Validate()

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("nonce"))
}

func TestRCARAttestationRequestValidate_MissingPrimaryEvidence(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	req := &RCARAttestationRequest{
		RuntimeData: RuntimeData{
			Nonce:     "test-nonce",
			TEEPubKey: JWK{Kty: "RSA", N: "abc", E: "AQAB"},
		},
	}
	err := req.Validate()

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("primary"))
}

func TestRCARAttestationRequestUnmarshalJSON_RejectsUnknownField(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	data := []byte(`{"runtime_data":{"nonce":"test","tee_pubkey":{"kty":"RSA","n":"abc","e":"AQAB"}},"tee_evidence":{"primary":"dGVzdA=="},"bad":"field"}`)
	var req RCARAttestationRequest
	err := json.Unmarshal(data, &req)

	g.Expect(err).To(gomega.HaveOccurred())
}

func TestParseResourceAddress(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	addr, err := ParseResourceAddress("default", "key", "my-tag")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(addr.Repository).To(gomega.Equal("default"))
	g.Expect(addr.Type).To(gomega.Equal("key"))
	g.Expect(addr.Tag).To(gomega.Equal("my-tag"))
}

func TestParseResourceAddress_RejectSlash(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	_, err := ParseResourceAddress("default/repo", "key", "my-tag")
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("cannot contain '/'"))
}

func TestInitDataUnmarshalJSON(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	data := []byte(`{"format":"toml","body":"version = \"0.1.0\"\nalgorithm = \"sha256\""}`)
	var initData InitData
	err := json.Unmarshal(data, &initData)

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(initData.Format).To(gomega.Equal("toml"))
	g.Expect(initData.Body).To(gomega.ContainSubstring("version"))
}

func TestInitDataOptional(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	// InitData with empty fields should be valid (both optional)
	data := []byte(`{"format":"","body":""}`)
	var initData InitData
	err := json.Unmarshal(data, &initData)

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(initData.Format).To(gomega.Equal(""))
	g.Expect(initData.Body).To(gomega.Equal(""))
}

func TestRCARAttestationRequestWithInitData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	data := []byte(`{
		"init-data":{"format":"json","body":"{}"},
		"runtime-data":{"nonce":"test","tee-pubkey":{"kty":"RSA","n":"abc","e":"AQAB"}},
		"tee-evidence":{"primary_evidence":"dGVzdA=="}
	}`)
	var req RCARAttestationRequest
	err := json.Unmarshal(data, &req)

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(req.InitData).NotTo(gomega.BeNil())
	g.Expect(req.InitData.Format).To(gomega.Equal("json"))
	g.Expect(req.InitData.Body).To(gomega.Equal("{}"))
}

func TestCompositeEvidenceWithAdditional(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	data := []byte(`{
		"runtime-data":{"nonce":"test","tee-pubkey":{"kty":"RSA","n":"abc","e":"AQAB"}},
		"tee-evidence":{
			"primary_evidence":"dGVzdA==",
			"additional_evidence":"{\"sgx\":{\"quote\":\"test\"}}"
		}
	}`)
	var req RCARAttestationRequest
	err := json.Unmarshal(data, &req)

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(req.TEEEvidence.AdditionalEvidence).To(gomega.Equal(`{"sgx":{"quote":"test"}}`))
}
