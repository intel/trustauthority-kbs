/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"intel/kbs/v1/model"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func testRSATEEPubKey(t *testing.T) model.JWK {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(priv.PublicKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	if len(eBytes) == 0 {
		eBytes = []byte{0}
	}
	return model.JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func TestRCARAuthSetsSessionCookie(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	h := createMockHandler(&MockService{})
	body := []byte(`{"version":"0.4.0","tee":"sgx","extra-params":{}}`)
	req, _ := http.NewRequest(http.MethodPost, "/kbs/v0/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", HTTPMediaTypeJson)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	g.Expect(rr.Code).To(gomega.Equal(http.StatusOK))
	g.Expect(rr.Result().Cookies()).NotTo(gomega.BeEmpty())

	var challenge map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &challenge)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(challenge).To(gomega.HaveKey("nonce"))
	g.Expect(challenge).NotTo(gomega.HaveKey("version")) // Version field removed from Challenge per Trustee spec
}

func TestRCARAttestRequiresSessionCookie(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	h := createMockHandler(&MockService{})
	body := []byte(`{"runtime-data":{"nonce":"test","tee-pubkey":{"kty":"RSA","n":"abc","e":"AQAB"}},"tee-evidence":{"primary_evidence":"dGVzdA=="}}`)
	req, _ := http.NewRequest(http.MethodPost, "/kbs/v0/attest", bytes.NewReader(body))
	req.Header.Set("Content-Type", HTTPMediaTypeJson)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	g.Expect(rr.Code).To(gomega.Equal(http.StatusUnauthorized))
}

func TestRCARAttestMarksSessionAttested(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockSvc := &MockService{}
	// Mock the VerifyRCARAttestation call to return a valid JWT-like token
	mockSvc.On("VerifyRCARAttestation", mock.AnythingOfType("*context.valueCtx"), mock.AnythingOfType("*model.RCARAttestationRequest")).
		Return("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrYnMiLCJhdWQiOiJrYnMiLCJzdWIiOiJ0ZXN0In0.fake", nil)
	h := createMockHandler(mockSvc)

	// Step 1: Call /auth to get nonce and cookie
	authReq, _ := http.NewRequest(http.MethodPost, "/kbs/v0/auth", bytes.NewReader([]byte(`{"version":"0.4.0","tee":"sgx","extra-params":{}}`)))
	authReq.Header.Set("Content-Type", HTTPMediaTypeJson)
	authRR := httptest.NewRecorder()
	h.ServeHTTP(authRR, authReq)

	g.Expect(authRR.Code).To(gomega.Equal(http.StatusOK))
	cookies := authRR.Result().Cookies()
	g.Expect(cookies).NotTo(gomega.BeEmpty())

	// Extract nonce from auth response
	var authChallenge map[string]interface{}
	err := json.Unmarshal(authRR.Body.Bytes(), &authChallenge)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	nonce := authChallenge["nonce"].(string)
	g.Expect(nonce).NotTo(gomega.BeEmpty())

	// Step 2: Call /attest with correct nonce from challenge
	attestBody := []byte(`{"runtime-data":{"nonce":"` + nonce + `","tee-pubkey":{"kty":"RSA","n":"abc","e":"AQAB"}},"tee-evidence":{"primary_evidence":"dGVzdA=="}}`)
	attestReq, _ := http.NewRequest(http.MethodPost, "/kbs/v0/attest", bytes.NewReader(attestBody))
	attestReq.Header.Set("Content-Type", HTTPMediaTypeJson)
	attestReq.AddCookie(cookies[0])
	attestRR := httptest.NewRecorder()
	h.ServeHTTP(attestRR, attestReq)

	g.Expect(attestRR.Code).To(gomega.Equal(http.StatusOK))

	var resp map[string]string
	err = json.Unmarshal(attestRR.Body.Bytes(), &resp)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp["token"]).NotTo(gomega.BeEmpty())
	// Token should be a JWT-like structure (header.payload.signature)
	tokenParts := bytes.Split([]byte(resp["token"]), []byte("."))
	g.Expect(tokenParts).To(gomega.HaveLen(3))
}

func TestRCARAttestNonceMismatchFails(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	h := createMockHandler(&MockService{})

	// Get auth cookie with nonce
	authReq, _ := http.NewRequest(http.MethodPost, "/kbs/v0/auth", bytes.NewReader([]byte(`{"version":"0.4.0","tee":"sgx","extra-params":{}}`)))
	authReq.Header.Set("Content-Type", HTTPMediaTypeJson)
	authRR := httptest.NewRecorder()
	h.ServeHTTP(authRR, authReq)

	g.Expect(authRR.Code).To(gomega.Equal(http.StatusOK))
	cookies := authRR.Result().Cookies()
	g.Expect(cookies).NotTo(gomega.BeEmpty())

	// Call /attest with WRONG nonce (should fail)
	attestBody := []byte(`{"runtime-data":{"nonce":"wrong-nonce","tee-pubkey":{"kty":"RSA","n":"abc","e":"AQAB"}},"tee-evidence":{"primary_evidence":"dGVzdA=="}}`)
	attestReq, _ := http.NewRequest(http.MethodPost, "/kbs/v0/attest", bytes.NewReader(attestBody))
	attestReq.Header.Set("Content-Type", HTTPMediaTypeJson)
	attestReq.AddCookie(cookies[0])
	attestRR := httptest.NewRecorder()
	h.ServeHTTP(attestRR, attestReq)

	// Should fail with 400 Bad Request (nonce mismatch)
	g.Expect(attestRR.Code).To(gomega.Equal(http.StatusBadRequest))

	var errResp map[string]interface{}
	err := json.Unmarshal(attestRR.Body.Bytes(), &errResp)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(errResp["detail"]).To(gomega.ContainSubstring("nonce"))
}

func TestRCARResourceWithBearerToken(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockSvc := &MockService{}
	// Mock the VerifyRCARAttestation call to return a valid JWT-like token
	mockSvc.On("VerifyRCARAttestation", mock.AnythingOfType("*context.valueCtx"), mock.AnythingOfType("*model.RCARAttestationRequest")).
		Return("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrYnMiLCJhdWQiOiJrYnMiLCJzdWIiOiJ0ZXN0In0.fake", nil)
	mockSvc.On("GetRCARResource", mock.Anything, mock.AnythingOfType("*model.ResourceAddress")).
		Return([]byte("my-secret-resource"), nil)
	h := createMockHandler(mockSvc)

	authReq, _ := http.NewRequest(http.MethodPost, "/kbs/v0/auth", bytes.NewReader([]byte(`{"version":"0.4.0","tee":"sgx","extra-params":{}}`)))
	authReq.Header.Set("Content-Type", HTTPMediaTypeJson)
	authRR := httptest.NewRecorder()
	h.ServeHTTP(authRR, authReq)

	g.Expect(authRR.Code).To(gomega.Equal(http.StatusOK))
	cookies := authRR.Result().Cookies()
	g.Expect(cookies).NotTo(gomega.BeEmpty())

	var authChallenge map[string]interface{}
	err := json.Unmarshal(authRR.Body.Bytes(), &authChallenge)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	nonce := authChallenge["nonce"].(string)
	teePub := testRSATEEPubKey(t)

	attReq := model.RCARAttestationRequest{
		RuntimeData: model.RuntimeData{
			Nonce:     nonce,
			TEEPubKey: teePub,
		},
		TEEEvidence: model.CompositeEvidence{PrimaryEvidence: json.RawMessage(`"dGVzdA=="`)},
	}
	attestBody, err := json.Marshal(attReq)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	attestReq, _ := http.NewRequest(http.MethodPost, "/kbs/v0/attest", bytes.NewReader(attestBody))
	attestReq.Header.Set("Content-Type", HTTPMediaTypeJson)
	attestReq.AddCookie(cookies[0])
	attestRR := httptest.NewRecorder()
	h.ServeHTTP(attestRR, attestReq)

	g.Expect(attestRR.Code).To(gomega.Equal(http.StatusOK))

	var attestResp map[string]string
	err = json.Unmarshal(attestRR.Body.Bytes(), &attestResp)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	token := attestResp["token"]
	g.Expect(token).NotTo(gomega.BeEmpty())

	resourceReq, _ := http.NewRequest(http.MethodGet, "/kbs/v0/resource/default/key/11111111-1111-1111-1111-111111111111", nil)
	resourceReq.Header.Set("Authorization", "Bearer "+token)
	resourceRR := httptest.NewRecorder()
	h.ServeHTTP(resourceRR, resourceReq)

	g.Expect(resourceRR.Code).To(gomega.Equal(http.StatusOK))

	var resp map[string]string
	err = json.Unmarshal(resourceRR.Body.Bytes(), &resp)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp["protected"]).NotTo(gomega.BeEmpty())
	g.Expect(resp["encrypted_key"]).NotTo(gomega.BeEmpty())
	g.Expect(resp["aad"]).NotTo(gomega.BeEmpty())
	g.Expect(resp["iv"]).NotTo(gomega.BeEmpty())
	g.Expect(resp["ciphertext"]).NotTo(gomega.BeEmpty())
	g.Expect(resp["tag"]).NotTo(gomega.BeEmpty())
}

func TestRCARResourceBearerTokenInvalid(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	h := createMockHandler(&MockService{})

	resourceReq, _ := http.NewRequest(http.MethodGet, "/kbs/v0/resource/default/key/my-tag", nil)
	resourceReq.Header.Set("Authorization", "Bearer invalid-token")
	resourceRR := httptest.NewRecorder()
	h.ServeHTTP(resourceRR, resourceReq)

	g.Expect(resourceRR.Code).To(gomega.Equal(http.StatusUnauthorized))

	var problem map[string]interface{}
	err := json.Unmarshal(resourceRR.Body.Bytes(), &problem)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(problem["detail"]).To(gomega.Equal("invalid bearer token"))
}

func TestRCARResourceCookieTakesPrecedenceOverBearer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	h := createMockHandler(&MockService{})

	// No valid cookie session, but invalid bearer token. Since cookie lookup fails,
	// bearer path is used and should reject.
	resourceReq, _ := http.NewRequest(http.MethodGet, "/kbs/v0/resource/default/key/my-tag", nil)
	resourceReq.AddCookie(&http.Cookie{Name: rcarSessionCookieName, Value: "non-existent"})
	resourceReq.Header.Set("Authorization", "Bearer invalid-token")
	resourceRR := httptest.NewRecorder()
	h.ServeHTTP(resourceRR, resourceReq)

	g.Expect(resourceRR.Code).To(gomega.Equal(http.StatusUnauthorized))

	var problem map[string]interface{}
	err := json.Unmarshal(resourceRR.Body.Bytes(), &problem)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(problem["detail"]).To(gomega.Equal("invalid or expired session"))
}
