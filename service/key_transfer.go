/*
 *   Copyright (c) 2024-2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"intel/kbs/v1/constant"
	"intel/kbs/v1/crypt"
	"intel/kbs/v1/keymanager"
	"intel/kbs/v1/model"

	"github.com/google/uuid"
	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	ivSize   = 4
	tagSize  = 4
	wrapSize = 4
)

type TransferKeyRequest struct {
	KeyId              uuid.UUID
	PublicKey          *rsa.PublicKey
	AttestationType    string
	KeyTransferRequest *model.KeyTransferRequest
}

type TransferKeyResponse struct {
	AttestationType     string
	Nonce               *itaConnector.VerifierNonce
	KeyTransferResponse *model.KeyTransferResponse
}

// itaV2EvidenceTDX is the TDX sub-object sent to ITA /appraisal/v2/attest.
type itaV2EvidenceTDX struct {
	Quote       []byte `json:"quote,omitempty"`
	RuntimeData []byte `json:"runtime_data,omitempty"`
	EventLog    []byte `json:"event_log,omitempty"`
}

// itaV2EvidenceSGX is the SGX sub-object sent to ITA /appraisal/v2/attest.
// SGX evidence has no event log (no RTMRs).
type itaV2EvidenceSGX struct {
	Quote       []byte `json:"quote,omitempty"`
	RuntimeData []byte `json:"runtime_data,omitempty"`
}

// itaV2AttestRequest is the full body sent to ITA /appraisal/v2/attest.
// SGX and TDX are mutually exclusive; NVGPU can only accompany TDX.
type itaV2AttestRequest struct {
	PolicyIds []uuid.UUID       `json:"policy_ids,omitempty"`
	SGX       *itaV2EvidenceSGX `json:"sgx,omitempty"`
	TDX       *itaV2EvidenceTDX `json:"tdx,omitempty"`
	NVGPU     json.RawMessage   `json:"nvgpu,omitempty"`
}

func (mw loggingMiddleware) TransferKeyWithEvidence(ctx context.Context, req TransferKeyRequest) (*TransferKeyResponse, error) {
	var err error
	defer func(begin time.Time) {
		logrus.Tracef("TransferKeyWithEvidence took %s since %s", time.Since(begin), begin)
		if err != nil {
			logrus.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.TransferKeyWithEvidence(ctx, req)
	return resp, err
}

func (svc service) TransferKeyWithEvidence(ctx context.Context, req TransferKeyRequest) (*TransferKeyResponse, error) {
	key, err := svc.remoteManager.RetrieveKey(req.KeyId)
	if err != nil {
		if err.Error() == RecordNotFound {
			logrus.WithError(err).Error("Key with specified id doesn't exist")
			return nil, &HandledError{Code: http.StatusNotFound, Message: "Key with specified id does not exist"}
		} else {
			logrus.WithError(err).Error("Key retrieval failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve key"}
		}
	}

	transferPolicy, err := svc.repository.KeyTransferPolicyStore.Retrieve(key.TransferPolicyID)
	if err != nil {
		logrus.WithError(err).Error("Key transfer policy retrieve failed")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve key transfer policy for the key"}
	}

	var token string
	itaRequestID := req.KeyId.String()

	if req.AttestationType == "" {
		// Passport mode: client provides a pre-obtained attestation token.
		// Nonce issuance is disabled in this phase — no GetNonce() call.
		if req.KeyTransferRequest.AttestationToken == "" {
			logrus.Error("Request has no attestation_token and no Attestation-Type header")
			return nil, &HandledError{Code: http.StatusBadRequest, Message: "attestation_token or Attestation-Type header is required"}
		}
		token = req.KeyTransferRequest.AttestationToken
	} else {
		// Background mode: client provides raw evidence; KBS obtains the token.
		if !transferPolicy.AttestationType.Contains(model.AttesterType(req.AttestationType)) {
			logrus.Error("attestation-type in request header is not in key-transfer policy")
			return nil, &HandledError{Code: http.StatusUnauthorized, Message: "attestation-type in request header does not match with attestation-type in key-transfer policy"}
		}

		policyIds := getPolicyIDsForAttestationTypes(transferPolicy)

		if len(req.KeyTransferRequest.NVGPU) > 0 && req.KeyTransferRequest.V2SGX {
			// Defense-in-depth: SGX+NVGPU should have been rejected by UnmarshalJSON.
			logrus.Error("nvgpu evidence is not valid with sgx evidence")
			return nil, &HandledError{Code: http.StatusBadRequest, Message: "nvgpu evidence is not valid with sgx evidence"}
		}

		if len(req.KeyTransferRequest.NVGPU) > 0 {
			// Composite TDX+NVGPU: call ITA v2 attest endpoint directly.
			token, err = svc.getTokenV2(
				ctx,
				req.KeyTransferRequest.Quote,
				req.KeyTransferRequest.RuntimeData,
				req.KeyTransferRequest.EventLog,
				policyIds,
				req.KeyTransferRequest.NVGPU,
				itaRequestID,
			)
		} else if req.KeyTransferRequest.V2SGX {
			// SGX V2: call ITA v2 attest endpoint with nested SGX evidence.
			token, err = svc.getTokenV2SGX(
				ctx,
				req.KeyTransferRequest.Quote,
				req.KeyTransferRequest.RuntimeData,
				policyIds,
				itaRequestID,
			)
		} else {
			// TDX/SGX V1: use go-connector.
			evidence := itaConnector.Evidence{
				Evidence: req.KeyTransferRequest.Quote,
				UserData: req.KeyTransferRequest.RuntimeData,
				EventLog: req.KeyTransferRequest.EventLog,
			}
			tokenRequest := itaConnector.GetTokenArgs{
				Nonce:     nil, // nonce disabled this phase
				Evidence:  &evidence,
				PolicyIds: policyIds,
				RequestId: itaRequestID,
			}
			tokenResp, err2 := svc.itaClient.GetToken(tokenRequest)
			if err2 != nil {
				logrus.WithError(err2).Error("Error retrieving token from Trust Authority service")
				return nil, &HandledError{Code: http.StatusBadGateway, Message: "Error retrieving token from Trust Authority service"}
			}
			token = tokenResp.Token
		}
		if err != nil {
			logrus.WithError(err).Error("Error retrieving token from Trust Authority service")
			return nil, &HandledError{Code: http.StatusBadGateway, Message: "Error retrieving token from Trust Authority service"}
		}
	}

	claims, err := svc.authenticateToken(token)
	if err != nil {
		logrus.WithError(err).Error("Failed to authenticate attestation-token")
		return nil, &HandledError{Code: http.StatusUnauthorized, Message: "Failed to authenticate attestation-token"}
	}

	tokenClaims := claims.(*model.AttestationTokenClaim)

	transferResponse, httpStatus, err := svc.validateClaimsAndGetKey(tokenClaims, transferPolicy, key.KeyInfo.Algorithm, tokenClaims.AttesterHeldData, req.KeyId)
	if err != nil {
		return nil, &HandledError{Code: httpStatus, Message: err.Error()}
	}

	resp := &TransferKeyResponse{
		AttestationType:     tokenClaims.AttesterType.String(),
		KeyTransferResponse: transferResponse.(*model.KeyTransferResponse),
	}
	return resp, nil
}

func (svc service) authenticateToken(token string) (interface{}, error) {
	version := detectTokenVersion(token)
	if strings.HasPrefix(version, "2") {
		// ITA v2 token path
		claimsV2 := &model.AttestationTokenV2Claim{}
		jwtToken, err := svc.itaClient.VerifyToken(token)
		if err != nil {
			return nil, errors.Wrap(err, "Error while verifying the token")
		}
		_, err = crypt.GetTokenClaims(jwtToken, token, claimsV2)
		if err != nil {
			return nil, errors.Wrap(err, "Error while parsing the token claims")
		}
		return claimsV2.ToAttestationTokenClaim(), nil
	}
	// ITA v1 token path (existing behavior, unchanged)
	claims := &model.AttestationTokenClaim{}
	jwtToken, err := svc.itaClient.VerifyToken(token)
	if err != nil {
		return nil, errors.Wrap(err, "Error while verifying the token")
	}
	_, err = crypt.GetTokenClaims(jwtToken, token, claims)
	if err != nil {
		return nil, errors.Wrap(err, "Error while parsing the token claims")
	}
	return claims, nil
}

func (svc service) validateClaimsAndGetKey(tokenClaims *model.AttestationTokenClaim, transferPolicy *model.KeyTransferPolicy, keyAlgorithm, userData string, keyId uuid.UUID) (interface{}, int, error) {

	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to validate Token claims against Key transfer policy attributes")
		return nil, http.StatusUnauthorized, &HandledError{Message: "Token claims validation against key-transfer-policy failed"}
	}

	kt, err := transferPolicy.AttestationType.KeyWrappingAttesterType()
	if err != nil {
		logrus.WithError(err).Error("no key-wrapping attester type in policy")
		return nil, http.StatusInternalServerError, &HandledError{Message: "policy has no key-wrapping attester type"}
	}
	return svc.getWrappedKey(keyAlgorithm, userData, keyId, kt)
}

func (svc service) getWrappedKey(keyAlgorithm, userData string, id uuid.UUID, attesterType model.AttesterType) (interface{}, int, error) {

	publicKey, err := getPublicKey(userData, attesterType)
	if err != nil {
		logrus.WithError(err).Error("Error in getting public key")
		return nil, http.StatusInternalServerError, &HandledError{Message: "Error in getting public key"}
	}

	secretKey, status, err := getSecretKey(svc.remoteManager, id)
	defer crypt.ZeroizeByteArray(secretKey)
	if err != nil {
		return nil, status, err
	}

	swk, err := createSwk()
	defer crypt.ZeroizeByteArray(swk)
	if err != nil {
		logrus.Error("Error in creating SWK key")
		return nil, http.StatusInternalServerError, &HandledError{Message: "Error in creating SWK key"}
	}

	var bytes, keyByte, nonceByte []byte
	switch keyAlgorithm {
	case constant.CRYPTOALGAES:
		keyByte = secretKey

	case constant.CRYPTOALGRSA:
		privatePem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: secretKey,
			},
		)

		decodedBlock, _ := pem.Decode(privatePem)
		if decodedBlock == nil {
			logrus.Error("Failed to decode secret key")
			return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to decode secret key"}
		}
		keyByte = decodedBlock.Bytes
		defer crypt.ZeroizeByteArray(decodedBlock.Bytes)
		defer crypt.ZeroizeByteArray(privatePem)

	case constant.CRYPTOALGEC:
		privatePem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: secretKey,
			},
		)

		decodedBlock, _ := pem.Decode(privatePem)
		if decodedBlock == nil {
			logrus.Error("Failed to decode secret key")
			return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to decode secret key"}
		}
		keyByte = decodedBlock.Bytes
		defer crypt.ZeroizeByteArray(decodedBlock.Bytes)
		defer crypt.ZeroizeByteArray(privatePem)
	}

	defer crypt.ZeroizeByteArray(keyByte)
	// Wrap secret key with swk
	bytes, nonceByte, err = AesEncrypt(keyByte, swk)
	if err != nil {
		logrus.Error("Failed to encrypt secret key with swk")
		return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to encrypt secret key with swk"}
	}

	keyMetaDataSize := ivSize + tagSize + wrapSize
	ivLength := len(nonceByte)
	keyMetaData := make([]byte, keyMetaDataSize)
	binary.LittleEndian.PutUint32(keyMetaData[0:], uint32(ivLength))
	binary.LittleEndian.PutUint32(keyMetaData[4:], uint32(16))
	binary.LittleEndian.PutUint32(keyMetaData[8:], uint32(len(bytes)))

	wrappedKey := []byte{}
	wrappedKey = append(wrappedKey, keyMetaData...)
	wrappedKey = append(wrappedKey, nonceByte...)
	wrappedKey = append(wrappedKey, bytes...)

	// Wrap SWK with public key
	wrappedSWK, status, err := wrapKey(publicKey, swk, sha256.New(), nil)
	if err != nil {
		return nil, status, err
	}

	transferResponse := &model.KeyTransferResponse{
		WrappedKey: wrappedKey,
		WrappedSWK: wrappedSWK.([]byte),
	}
	return transferResponse, http.StatusOK, nil
}

func getPublicKey(userData string, attesterType model.AttesterType) (*rsa.PublicKey, error) {

	key, err := base64.StdEncoding.DecodeString(userData)
	if err != nil {
		return nil, errors.New("failed to decode user data")
	}
	if len(key) < 5 {
		return nil, errors.New("attester held data is missing or invalid")
	}
	// If the decoded bytes are PEM-encoded (e.g. produced by trustauthority-cli or
	// standard OpenSSL/Go tools), parse them as a standard PKIX public key.
	// This handles TDX attesters that embed the public key as a PEM block in user_data.
	if block, _ := pem.Decode(key); block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PEM public key")
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key in user_data is not an RSA key")
		}
		if rsaPub.N.BitLen() <= 2048 {
			return nil, errors.New("RSA key size must be greater than 2048 bits")
		}
		return rsaPub, nil
	}

	// Legacy raw binary format: [4-byte exponent][modulus]
	// SGX enclaves transmit in Little Endian; all others use Big Endian.
	modArr := key[4:]
	var eb uint32
	n := big.Int{}

	if attesterType == model.SGX {
		// Endianess : Key Buffer transmitted from Enclave is in LE
		for i := 0; i < len(modArr)/2; i++ {
			modArr[i], modArr[len(modArr)-i-1] = modArr[len(modArr)-i-1], modArr[i]
		}
	}
	eb = binary.LittleEndian.Uint32(key[:])
	n.SetBytes(modArr)

	// imposing lower limit on the size of the public key for enhanced security reasons
	if n.BitLen() <= 2048 {
		return nil, errors.New("RSA key size must be greater than 2048 bits")
	}

	pubKey := rsa.PublicKey{N: &n, E: int(eb)}
	return &pubKey, nil
}

func getSecretKey(remoteManager *keymanager.RemoteManager, id uuid.UUID) ([]byte, int, error) {

	secretKey, err := remoteManager.TransferKey(id)
	if err != nil {
		if err.Error() == RecordNotFound {
			logrus.Error("Key with specified id could not be located")
			return nil, http.StatusNotFound, &HandledError{Message: "Key with specified id does not exist"}
		} else {
			logrus.WithError(err).Error("Key transfer failed")
			return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to transfer Key"}
		}
	}
	return secretKey, http.StatusOK, nil
}

func wrapKey(publicKey *rsa.PublicKey, secretKey []byte, hash hash.Hash, label []byte) (interface{}, int, error) {

	// Wrap secret key with public key
	wrappedKey, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, secretKey, label)
	if err != nil {
		logrus.WithError(err).Error("Wrap key failed")
		return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to wrap key"}
	}

	return wrappedKey, http.StatusOK, nil
}

// createSwk - Function to create swk
func createSwk() ([]byte, error) {

	// create an AES Key here of 256 bits
	keyBytes, err := crypt.GetDerivedKey(32)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate random key bytes")
	}
	return keyBytes, nil
}

// AesEncrypt encrypts plain bytes using AES key passed as param
func AesEncrypt(data, key []byte) ([]byte, []byte, error) {

	// generate a new aes cipher using key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal

	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// here we encrypt data using the Seal function
	return gcm.Seal(nil, nonce, data, nil), nonce, nil
}

// getPolicyIDsForAttestationTypes collects PolicyIds from the sub-policies that
// are actually listed in transferPolicy.AttestationType.  Sub-policy objects that
// are present in the struct but whose type is absent from AttestationType are
// intentionally ignored so that stale entries do not contribute unexpected IDs.
func getPolicyIDsForAttestationTypes(transferPolicy *model.KeyTransferPolicy) []uuid.UUID {
	var policyIds []uuid.UUID
	seen := make(map[uuid.UUID]bool)
	addUnique := func(ids []uuid.UUID) {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				policyIds = append(policyIds, id)
			}
		}
	}
	if transferPolicy.AttestationType.Contains(model.SGX) && transferPolicy.SGX != nil {
		addUnique(transferPolicy.SGX.PolicyIds)
	}
	if transferPolicy.AttestationType.Contains(model.TDX) && transferPolicy.TDX != nil {
		addUnique(transferPolicy.TDX.PolicyIds)
	}
	if transferPolicy.AttestationType.Contains(model.NVGPU) && transferPolicy.NVGPU != nil {
		addUnique(transferPolicy.NVGPU.PolicyIds)
	}
	return policyIds
}

// getTokenV2 calls the ITA /appraisal/v2/attest endpoint for composite TDX+NVGPU
// evidence via the consolidated itaClient (AttestEvidence).
func (svc service) getTokenV2(ctx context.Context, quote, runtimeData, eventLog []byte, policyIds []uuid.UUID, nvgpu json.RawMessage, reqID string) (string, error) {
	tdxEvidence := &itaV2EvidenceTDX{
		Quote:       quote,
		RuntimeData: runtimeData,
		EventLog:    eventLog,
	}
	reqBody := itaV2AttestRequest{
		PolicyIds: policyIds,
		TDX:       tdxEvidence,
		NVGPU:     nvgpu,
	}
	resp, err := svc.itaClient.AttestEvidence(reqBody, "", reqID)
	if err != nil {
		return "", errors.Wrap(err, "ITA v2 attest request failed")
	}
	return resp.Token, nil
}

// getTokenV2SGX calls the ITA /appraisal/v2/attest endpoint for SGX-only V2
// evidence via the consolidated itaClient (AttestEvidence).
func (svc service) getTokenV2SGX(ctx context.Context, quote, runtimeData []byte, policyIds []uuid.UUID, reqID string) (string, error) {
	sgxEvidence := &itaV2EvidenceSGX{
		Quote:       quote,
		RuntimeData: runtimeData,
	}
	reqBody := itaV2AttestRequest{
		PolicyIds: policyIds,
		SGX:       sgxEvidence,
	}
	resp, err := svc.itaClient.AttestEvidence(reqBody, "", reqID)
	if err != nil {
		return "", errors.Wrap(err, "ITA v2 SGX attest request failed")
	}
	return resp.Token, nil
}

// buildITAV2EndpointURL builds the ITA v2 attest endpoint from TrustAuthorityApiUrl.
// It strips any existing path from baseURL so that a URL pre-configured with a
// versioned path (e.g. .../appraisal/v1) does not produce a double-path like
// .../appraisal/v1/appraisal/v2/attest.
// resourcePath should be "/attest".
func buildITAV2EndpointURL(baseURL, resourcePath string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		// Fallback: best-effort concatenation on unparseable input.
		base := strings.TrimRight(baseURL, "/")
		return base + "/appraisal/v2" + resourcePath
	}
	u.Path = "/appraisal/v2" + resourcePath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// detectTokenVersion returns the "ver" claim from a JWT without full verification.
// Returns "" on any error so callers can treat it as v1.
func detectTokenVersion(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Ver string `json:"ver"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Ver
}
