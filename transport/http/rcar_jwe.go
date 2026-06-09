/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"

	"intel/kbs/v1/model"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/pkg/errors"
)

type jweFlattened struct {
	Protected    string `json:"protected"`
	EncryptedKey string `json:"encrypted_key"`
	AAD          string `json:"aad"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	Tag          string `json:"tag"`
}

type jweGeneral struct {
	Protected    string `json:"protected"`
	EncryptedKey string `json:"encrypted_key,omitempty"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	Tag          string `json:"tag"`
	AAD          string `json:"aad,omitempty"`
	Recipients   []struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"recipients"`
}

func encryptResourceAsFlattenedJWE(teePubKey model.JWK, payload []byte) (*jweFlattened, error) {
	recipient, err := buildJWERecipient(teePubKey)
	if err != nil {
		return nil, err
	}

	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize JWE encrypter")
	}

	obj, err := encrypter.Encrypt(payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt resource")
	}

	full := obj.FullSerialize()
	var parsed jweGeneral
	if err := json.Unmarshal([]byte(full), &parsed); err != nil {
		return nil, errors.Wrap(err, "failed to parse JWE payload")
	}

	encryptedKey := parsed.EncryptedKey
	if encryptedKey == "" {
		if len(parsed.Recipients) == 0 {
			return nil, errors.New("missing JWE recipient")
		}
		encryptedKey = parsed.Recipients[0].EncryptedKey
	}

	aad := parsed.AAD
	if aad == "" {
		// RCAR protocol examples require explicit aad for AEAD payloads.
		aad = parsed.Protected
	}

	return &jweFlattened{
		Protected:    parsed.Protected,
		EncryptedKey: encryptedKey,
		AAD:          aad,
		IV:           parsed.IV,
		Ciphertext:   parsed.Ciphertext,
		Tag:          parsed.Tag,
	}, nil
}

func buildJWERecipient(jwk model.JWK) (jose.Recipient, error) {
	if jwk.IsRSA() {
		pk, err := rsaPublicKeyFromJWK(jwk)
		if err != nil {
			return jose.Recipient{}, err
		}
		alg, err := rsaAlgFromJWK(jwk.Alg)
		if err != nil {
			return jose.Recipient{}, err
		}
		return jose.Recipient{Algorithm: alg, Key: pk}, nil
	}

	if jwk.IsEC() {
		pk, err := ecPublicKeyFromJWK(jwk)
		if err != nil {
			return jose.Recipient{}, err
		}
		alg, err := ecAlgFromJWK(jwk.Alg)
		if err != nil {
			return jose.Recipient{}, err
		}
		return jose.Recipient{Algorithm: alg, Key: pk}, nil
	}

	return jose.Recipient{}, errors.Errorf("unsupported jwk kty %q", jwk.Kty)
}

func rsaAlgFromJWK(v string) (jose.KeyAlgorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "RSA-OAEP-256":
		return jose.RSA_OAEP_256, nil
	case "RSA-OAEP":
		return jose.RSA_OAEP, nil
	default:
		return "", errors.Errorf("unsupported rsa jwk alg %q", v)
	}
}

func ecAlgFromJWK(v string) (jose.KeyAlgorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	default:
		return "", errors.Errorf("unsupported ec jwk alg %q", v)
	}
}

func rsaPublicKeyFromJWK(jwk model.JWK) (*rsa.PublicKey, error) {
	nBytes, err := decodeB64URL(jwk.N)
	if err != nil {
		return nil, errors.Wrap(err, "invalid rsa jwk modulus")
	}
	eBytes, err := decodeB64URL(jwk.E)
	if err != nil {
		return nil, errors.Wrap(err, "invalid rsa jwk exponent")
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("invalid rsa jwk")
	}

	n := new(big.Int).SetBytes(nBytes)
	if n.Sign() <= 0 {
		return nil, errors.New("invalid rsa modulus")
	}
	if len(eBytes) > 8 {
		return nil, errors.New("invalid rsa exponent size")
	}
	var ebuf [8]byte
	copy(ebuf[8-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint64(ebuf[:]))
	if e <= 1 {
		return nil, errors.New("invalid rsa exponent")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func ecPublicKeyFromJWK(jwk model.JWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, errors.Errorf("unsupported ec curve %q", jwk.Crv)
	}

	xBytes, err := decodeB64URL(jwk.X)
	if err != nil {
		return nil, errors.Wrap(err, "invalid ec jwk x")
	}
	yBytes, err := decodeB64URL(jwk.Y)
	if err != nil {
		return nil, errors.Wrap(err, "invalid ec jwk y")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("ec jwk point is not on curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func decodeB64URL(v string) ([]byte, error) {
	if v == "" {
		return nil, errors.New("empty base64url value")
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(v)
}
