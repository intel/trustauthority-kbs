/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"

	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/jwt"
	"intel/amber/kbs/v1/model"
	cns "intel/amber/kbs/v1/repository/mocks/constants"
	"testing"
)

var (
	keyPair, _     = rsa.GenerateKey(rand.Reader, 2048)
	publicKey      = &keyPair.PublicKey
	pubKeyBytes, _ = x509.MarshalPKIXPublicKey(publicKey)
	publicKeyInPem = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	loadedPubKey, _ = loadPublicKey(pem.EncodeToMemory(publicKeyInPem))

	jwtTok             = &jwt.Token{}
	prodId      uint16 = 1
	isvSvn      uint16 = 0
	tokenClaims        = &model.AttestationTokenClaim{
		MrEnclave:    cns.ValidMrEnclave,
		MrSigner:     cns.ValidMrSigner,
		IsvProductId: &prodId,
		IsvSvn:       &isvSvn,
		Tee:          "SGX",
		TcbStatus:    "false",
		TeeHeldData:  base64.StdEncoding.EncodeToString(loadedPubKey),
	}
)

func TestKeyTransferRSA(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	t.Log("Pem Data:", base64.StdEncoding.EncodeToString(loadedPubKey))
	asClient.On("GetAttestationToken", mock.Anything).Return([]byte(""), nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.SignedNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:       []byte(""),
		SignedNonce: nonce,
		UserData:    []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              rsaKeyId,
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKey(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
func TestKeyTransfer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	tokenClaims.TcbStatus = "OUT_OF_DATE"
	tokenClaims.PolicyIds = []uuid.UUID{uuid.MustParse("232bffd9-7ab3-4bb5-bc6c-1852123d1a01")}
	asClient.On("GetAttestationToken", mock.Anything).Return([]byte(""), nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.SignedNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:       []byte(""),
		SignedNonce: nonce,
		UserData:    []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKey(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestTDXKeyTransfer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	jwtTok := &jwt.Token{}
	var seamSvn uint8 = 0

	tokenTDXClaims := &model.AttestationTokenClaim{
		MrSignerSeam: cns.ValidMrSignerSeam,
		MrSeam:       cns.ValidMrSeam,
		SeamSvn:      &seamSvn,
		MRTD:         cns.ValidMRTD,
		RTMR0:        cns.ValidRTMR0,
		RTMR1:        cns.ValidRTMR1,
		RTMR2:        cns.ValidRTMR2,
		RTMR3:        cns.ValidRTMR3,
		Tee:          "TDX",
		TcbStatus:    "false",
		TeeHeldData:  base64.StdEncoding.EncodeToString(loadedPubKey),
	}
	asClient.On("GetAttestationToken", mock.Anything).Return([]byte(""), nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenTDXClaims
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.SignedNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:       []byte(""),
		SignedNonce: nonce,
		UserData:    []byte(""),
	}

	request2 := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKey(context.Background(), request2)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
func loadPublicKey(userData []byte) ([]byte, error) {
	pubKeyBlock, _ := pem.Decode(userData)
	pubKeyBytes, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Public key format : <exponent:E_SIZE_IN_BYTES><modulus:N_SIZE_IN_BYTES>
	pub := pubKeyBytes.(*rsa.PublicKey)
	pubBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pubBytes, uint32(pub.E))
	pubBytes = append(pubBytes, pub.N.Bytes()...)
	return pubBytes, nil
}
func TestKeyTransferInvalidAttestaionType(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	jwtTok := &jwt.Token{}
	asClient.On("GetAttestationToken", mock.Anything).Return([]byte(""), nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.SignedNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:       []byte(""),
		SignedNonce: nonce,
		UserData:    []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              rsaKeyId,
		AttestationType:    "Invalid",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKey(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyTransferInvalidKeyId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	asClient.On("GetAttestationToken", mock.Anything).Return([]byte(""), nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.SignedNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:       []byte(""),
		SignedNonce: nonce,
		UserData:    []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.New(),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKey(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}
func TestKeyTransferInvalidSecretKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	asClient.On("GetAttestationToken", mock.Anything).Return([]byte(""), nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return(nil, errors.Errorf("Invalid Key"))

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.SignedNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:       []byte(""),
		SignedNonce: nonce,
		UserData:    []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKey(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestGetSecretKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tmpId := uuid.New()
	_, _, err := getSecretKey(kRemoteManager, tmpId)

	g.Expect(err).To(gomega.HaveOccurred())
}
