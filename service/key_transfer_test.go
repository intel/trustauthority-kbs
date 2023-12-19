/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"testing"

	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/jwt"
	"intel/amber/kbs/v1/model"
	cns "intel/amber/kbs/v1/repository/mocks/constants"

	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

var (
	publicKey = "AQABAEWpyf19e2eARCPq/l07CvkPGIoJK+48tDtv5sB5WswB2OY63qSxb+DxOrZ/b54BNF6xeS/+s7W81z+5RKQwmewIageZZByWHp0xs6eOnhoGMpdDEHFhIfp9an5e4wP8tnoaYyzeD66J5Wgd3gX+sBv6GL1BBRq4M1bNVslXcz4w3s4xWWO2CLfgSpI1jAToEhxLxta+e5Istn4v2hXsuEmkeSL5NHrcfy7AmPhFISUoyyJZ9121jEkW/yl/oGbJegfeWwD316Af69gawFCO29xjupnfQa7XCR+YrB2XTIqDqHAbo1fQabrdG3HlyIivyayFYz6moztv0VMnoAfUFzZ70ZvcefcI2HACo2qIJmathyoisuwH3aZ0Ojcg53rSBsTK9QN4jzyYkIg0Dl0prjzrIIyTxerDf+/R/YDTNy9KC6OCluZe0xLmYwFfOcPMr6taWVEPDM7K8Rmub5Hw02mCPXNhNjOTrPxM5wqrLbX5xJ5fJs33wlv5e+XVi2agjQ=="
	nonce     = &as.VerifierNonce{}

	jwtTok             = &jwt.Token{}
	prodId      uint16 = 1
	isvSvn      uint16 = 0
	tokenClaims        = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: prodId,
			SgxIsvSvn:    isvSvn,
		},
		AttesterHeldData: publicKey,
		VerifierNonce:    nonce,
		AttesterType:     "SGX",
	}
)

func TestKeyTransferRSA(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	asClient.On("GetAttestationToken", mock.Anything).Return("", nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              rsaKeyId,
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
func TestSGXKeyTransfer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	tokenClaims.AttesterTcbStatus = "OUT_OF_DATE"
	tokenClaims.PolicyIdsMatched = []model.PolicyClaim{{Id: uuid.MustParse("232bffd9-7ab3-4bb5-bc6c-1852123d1a01")}}
	asClient.On("GetAttestationToken", mock.Anything).Return("", nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestTDXKeyTransfer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	jwtTok := &jwt.Token{}
	var seamSvn uint8 = 0

	tokenTDXClaims := &model.AttestationTokenClaim{
		SGXClaims: nil,
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      seamSvn,
		},
		AttesterHeldData:  publicKey,
		AttesterTcbStatus: "false",
		AttesterType:      "TDX",
	}
	asClient.On("GetAttestationToken", mock.Anything).Return("", nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenTDXClaims
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
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
	binary.BigEndian.PutUint32(pubBytes, uint32(pub.E))
	pubBytes = append(pubBytes, pub.N.Bytes()...)
	return pubBytes, nil
}

func TestKeyTransferInvalidAttestaionType(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	jwtTok := &jwt.Token{}
	asClient.On("GetAttestationToken", mock.Anything).Return("", nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              rsaKeyId,
		AttestationType:    "Invalid",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyTransferInvalidKeyId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	asClient.On("GetAttestationToken", mock.Anything).Return("", nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.New(),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}
func TestKeyTransferInvalidSecretKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	asClient.On("GetAttestationToken", mock.Anything).Return("", nil)
	jwtVerifier.On("ValidateTokenAndGetClaims", mock.Anything, mock.AnythingOfType("**model.AttestationTokenClaim")).Return(jwtTok, nil).Run(func(args mock.Arguments) {
		tClaims := args.Get(1).(**model.AttestationTokenClaim)
		*tClaims = tokenClaims
		t.Log("values:", *tClaims)
	}).Once()

	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return(nil, errors.Errorf("Invalid Key"))

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &as.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestGetSecretKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tmpId := uuid.New()
	_, _, err := getSecretKey(kRemoteManager, tmpId)

	g.Expect(err).To(gomega.HaveOccurred())
}
