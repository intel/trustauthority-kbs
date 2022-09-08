/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"hash"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/keymanager"
	"intel/amber/kbs/v1/model"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
	Nonce               *as.Nonce
	KeyTransferResponse *model.KeyTransferResponse
}

func (mw loggingMiddleware) TransferKeyWithEvidence(ctx context.Context, req TransferKeyRequest) (*TransferKeyResponse, error) {
	var err error
	defer func(begin time.Time) {
		log.Tracef("TransferKeyWithEvidence took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.TransferKeyWithEvidence(ctx, req)
	return resp, err
}

func (svc service) TransferKeyWithEvidence(_ context.Context, req TransferKeyRequest) (*TransferKeyResponse, error) {
	key, err := svc.remoteManager.RetrieveKey(req.KeyId)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.WithError(err).Error("Key with specified id doesn't exist")
			return nil, &HandledError{Code: http.StatusNotFound, Message: "Key with specified id does not exist"}
		} else {
			log.WithError(err).Error("Key retrieval failed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve key"}
		}
	}

	transferPolicy, err := svc.repository.KeyTransferPolicyStore.Retrieve(key.TransferPolicyID)
	if err != nil {
		log.WithError(err).Error("Key transfer policy retrieve failed")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "Failed to retrieve key transfer policy"}
	}

	var token []byte
	if req.AttestationType == "" {
		if req.KeyTransferRequest.AttestationToken == "" {
			nonce, err := svc.asClient.GetNonce()
			if err != nil {
				log.WithError(err).Error("Error retrieving nonce from appraisal service")
				return nil, &HandledError{Code: http.StatusBadGateway, Message: "Error retrieving nonce from appraisal service"}
			}

			resp := &TransferKeyResponse{
				Nonce:               nonce,
				AttestationType:     transferPolicy.AttestationType[0].String(),
				KeyTransferResponse: nil,
			}
			return resp, nil
		} else {
			token = []byte(req.KeyTransferRequest.AttestationToken)
		}
	} else {
		if req.AttestationType != transferPolicy.AttestationType[0].String() {
			log.Error("attestation-type in request header does not match with attestation-type in key-transfer policy")
			return nil, &HandledError{Code: http.StatusUnauthorized, Message: "attestation-type in request header does not match with attestation-type in key-transfer policy"}
		}

		var policyIds []uuid.UUID
		switch transferPolicy.AttestationType[0] {
		case model.SGX:
			policyIds = transferPolicy.SGX.PolicyIds

		case model.TDX:
			policyIds = transferPolicy.TDX.PolicyIds
		}

		tokenRequest := as.AttestationTokenRequest{
			Quote:     req.KeyTransferRequest.Quote,
			Nonce:     req.KeyTransferRequest.Nonce,
			UserData:  req.KeyTransferRequest.UserData,
			PolicyIds: policyIds,
			EventLog:  req.KeyTransferRequest.EventLog,
		}

		token, err = svc.asClient.GetAttestationToken(&tokenRequest)
		if err != nil {
			log.WithError(err).Error("Error retrieving token from appraisal service")
			return nil, &HandledError{Code: http.StatusBadGateway, Message: "Error retrieving token from appraisal service"}
		}
	}

	claims, err := svc.authenticateToken(string(token))
	if err != nil {
		log.WithError(err).Error("Failed to authenticate attestation-token")
		return nil, &HandledError{Code: http.StatusUnauthorized, Message: "Failed to authenticate attestation-token"}
	}

	tokenClaims := claims.(*model.AttestationTokenClaim)
	if tokenClaims.AmberEvidenceType != transferPolicy.AttestationType[0] {
		log.Error("attestation-token is not valid for attestation-type in key-transfer policy")
		return nil, &HandledError{Code: http.StatusUnauthorized, Message: "attestation-token is not valid for attestation-type in key-transfer policy"}
	}

	transferResponse, httpStatus, err := svc.validateClaimsAndGetKey(tokenClaims, transferPolicy, key.KeyInfo.Algorithm, tokenClaims.AmberTeeHeldData, req.KeyId)
	if err != nil {
		return nil, &HandledError{Code: httpStatus, Message: err.Error()}
	}

	resp := &TransferKeyResponse{
		KeyTransferResponse: transferResponse.(*model.KeyTransferResponse),
	}
	return resp, nil
}

func (svc service) authenticateToken(token string) (interface{}, error) {

	claims := &model.AttestationTokenClaim{}
	_, err := svc.jwtVerifier.ValidateTokenAndGetClaims(strings.TrimSpace(token), &claims)
	if err != nil {
		return nil, errors.Wrap(err, "token validation failure")
	}

	return claims, nil
}

func (svc service) validateClaimsAndGetKey(tokenClaims *model.AttestationTokenClaim, transferPolicy *model.KeyTransferPolicy, keyAlgorithm, userData string, keyId uuid.UUID) (interface{}, int, error) {

	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	if err != nil {
		log.WithError(err).Errorf("Failed to validate Token claims against Key transfer policy attributes")
		return nil, http.StatusUnauthorized, &HandledError{Message: "Token claims validation against key-transfer-policy failed"}
	}

	return svc.getWrappedKey(keyAlgorithm, userData, keyId)
}

func (svc service) getWrappedKey(keyAlgorithm, userData string, id uuid.UUID) (interface{}, int, error) {

	publicKey, err := getPublicKey(userData)
	if err != nil {
		log.WithError(err).Error("Error in getting public key")
		return nil, http.StatusInternalServerError, &HandledError{Message: "Error in getting public key"}
	}

	secretKey, status, err := getSecretKey(svc.remoteManager, id)
	if err != nil {
		return nil, status, err
	}

	swk, err := CreateSwk()
	if err != nil {
		log.Error("Error in creating SWK key")
		return nil, http.StatusInternalServerError, &HandledError{Message: "Error in creating SWK key"}
	}

	var bytes, keyByte, nonceByte []byte
	switch keyAlgorithm {
	case constant.CRYPTOALGAES:
		keyByte = secretKey.([]byte)

	case constant.CRYPTOALGRSA:
		privatePem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: secretKey.([]byte),
			},
		)

		decodedBlock, _ := pem.Decode(privatePem)
		if decodedBlock == nil {
			log.Error("Failed to decode secret key")
			return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to decode secret key"}
		}
		keyByte = decodedBlock.Bytes

	case constant.CRYPTOALGEC:
		privatePem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: secretKey.([]byte),
			},
		)

		decodedBlock, _ := pem.Decode(privatePem)
		if decodedBlock == nil {
			log.Error("Failed to decode secret key")
			return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to decode secret key"}
		}
		keyByte = decodedBlock.Bytes
	}

	// Wrap secret key with swk
	bytes, nonceByte, err = AesEncrypt(keyByte, swk)
	if err != nil {
		log.Error("Failed to encrypt secret key with swk")
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

func getPublicKey(userData string) (*rsa.PublicKey, error) {

	key, err := base64.StdEncoding.DecodeString(userData)
	if err != nil {
		return nil, errors.New("failed to decode user data")
	}

	modArr := key[4:]
	// Endianess : Key Buffer transmitted from Enclave is in LE.
	for i := 0; i < len(modArr)/2; i++ {
		modArr[i], modArr[len(modArr)-i-1] = modArr[len(modArr)-i-1], modArr[i]
	}

	n := big.Int{}
	n.SetBytes(modArr)
	eb := binary.LittleEndian.Uint32(key[:])
	pubKey := rsa.PublicKey{N: &n, E: int(eb)}

	return &pubKey, nil
}

func getSecretKey(remoteManager *keymanager.RemoteManager, id uuid.UUID) (interface{}, int, error) {

	secretKey, err := remoteManager.TransferKey(id)
	if err != nil {
		if err.Error() == RecordNotFound {
			log.Error("Key with specified id could not be located")
			return nil, http.StatusNotFound, &HandledError{Message: "Key with specified id does not exist"}
		} else {
			log.WithError(err).Error("Key transfer failed")
			return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to transfer Key"}
		}
	}
	return secretKey, http.StatusOK, nil
}

func wrapKey(publicKey *rsa.PublicKey, secretKey []byte, hash hash.Hash, label []byte) (interface{}, int, error) {

	// Wrap secret key with public key
	wrappedKey, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, secretKey, label)
	if err != nil {
		log.WithError(err).Error("Wrap key failed")
		return nil, http.StatusInternalServerError, &HandledError{Message: "Failed to wrap key"}
	}

	return wrappedKey, http.StatusOK, nil
}

// CreateSwk - Function to create swk
func CreateSwk() ([]byte, error) {

	// create an AES Key here of 256 bits
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
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
