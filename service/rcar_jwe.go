/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"

	"intel/kbs/v1/crypt"
	"intel/kbs/v1/model"

	jose "github.com/go-jose/go-jose/v4"
	josecipher "github.com/go-jose/go-jose/v4/cipher"
	"github.com/pkg/errors"
)

const gcmTagSize = 16

func encryptResourceAsFlattenedJWE(teePubKey *model.JWK, payload []byte) (*model.JWEFlattened, error) {
	if teePubKey.IsRSA() {
		pk, err := rsaPublicKeyFromJWK(teePubKey)
		if err != nil {
			return nil, err
		}
		alg, err := rsaAlgFromJWK(teePubKey.Alg)
		if err != nil {
			return nil, err
		}
		return encryptRSAAsFlattenedJWE(pk, alg, payload)
	}

	if teePubKey.IsEC() {
		pk, err := ecPublicKeyFromJWK(teePubKey)
		if err != nil {
			return nil, err
		}
		alg, err := ecAlgFromJWK(teePubKey.Alg)
		if err != nil {
			return nil, err
		}
		return encryptECDHESA256KWAsFlattenedJWE(pk, alg, payload)
	}

	return nil, errors.Errorf("unsupported jwk kty %q", teePubKey.Kty)
}

func encryptRSAAsFlattenedJWE(pk *rsa.PublicKey, alg jose.KeyAlgorithm, payload []byte) (*model.JWEFlattened, error) {
	protected, err := marshalProtectedHeader(protectedHeader{
		Alg: string(alg),
		Enc: "A256GCM",
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize protected header")
	}

	cek, err := createSwk()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate content encryption key")
	}
	defer crypt.ZeroizeByteArray(cek)
	iv, ciphertext, tag, err := encryptA256GCM(cek, []byte(protected), payload)
	if err != nil {
		return nil, err
	}

	var encryptedKey []byte
	switch alg {
	case jose.RSA_OAEP_256:
		wrappedKey, _, wrapErr := wrapKey(pk, cek, sha256.New(), nil)
		if wrapErr != nil {
			return nil, wrapErr
		}

		var ok bool
		encryptedKey, ok = wrappedKey.([]byte)
		if !ok {
			return nil, errors.New("failed to convert wrapped key bytes")
		}
	default:
		return nil, errors.Errorf("unsupported rsa jwk alg %q", alg)
	}

	return &model.JWEFlattened{
		Protected:    protected,
		EncryptedKey: base64.RawURLEncoding.EncodeToString(encryptedKey),
		IV:           base64.RawURLEncoding.EncodeToString(iv),
		Ciphertext:   base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:          base64.RawURLEncoding.EncodeToString(tag),
	}, nil
}

func encryptECDHESA256KWAsFlattenedJWE(pk *ecdsa.PublicKey, alg jose.KeyAlgorithm, payload []byte) (*model.JWEFlattened, error) {
	ephemeralPriv, err := ecdsa.GenerateKey(pk.Curve, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ephemeral ec key")
	}
	defer crypt.ZeroizeECDSAPrivateKey(ephemeralPriv)

	kek := josecipher.DeriveECDHES(string(alg), []byte{}, []byte{}, ephemeralPriv, pk, 32)
	defer crypt.ZeroizeByteArray(kek)
	cek, err := createSwk()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate content encryption key")
	}
	defer crypt.ZeroizeByteArray(cek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize key wrap cipher")
	}
	encryptedKey, err := josecipher.KeyWrap(block, cek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to wrap content encryption key")
	}

	curveName, coordLen, err := ecCurveMetadata(pk.Curve)
	if err != nil {
		return nil, err
	}
	ephemeralX := base64.RawURLEncoding.EncodeToString(bigIntToFixedBytes(ephemeralPriv.PublicKey.X, coordLen))
	ephemeralY := base64.RawURLEncoding.EncodeToString(bigIntToFixedBytes(ephemeralPriv.PublicKey.Y, coordLen))

	protected, err := marshalProtectedHeader(protectedHeader{
		Alg: string(alg),
		Enc: "A256GCM",
		EPK: &epkHeader{
			Crv: curveName,
			Kty: "EC",
			X:   ephemeralX,
			Y:   ephemeralY,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize protected header")
	}

	iv, ciphertext, tag, err := encryptA256GCM(cek, []byte(protected), payload)
	if err != nil {
		return nil, err
	}

	return &model.JWEFlattened{
		Protected:    protected,
		EncryptedKey: base64.RawURLEncoding.EncodeToString(encryptedKey),
		IV:           base64.RawURLEncoding.EncodeToString(iv),
		Ciphertext:   base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:          base64.RawURLEncoding.EncodeToString(tag),
	}, nil
}

func encryptA256GCM(cek []byte, aad []byte, payload []byte) ([]byte, []byte, []byte, error) {
	sealed, iv, err := AesEncryptWithAAD(payload, cek, aad)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to encrypt payload")
	}
	if len(sealed) < gcmTagSize {
		return nil, nil, nil, errors.New("invalid gcm output")
	}

	ciphertext := sealed[:len(sealed)-gcmTagSize]
	tag := sealed[len(sealed)-gcmTagSize:]
	return iv, ciphertext, tag, nil
}

func marshalProtectedHeader(h protectedHeader) (string, error) {
	raw, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func ecCurveMetadata(curve elliptic.Curve) (string, int, error) {
	switch curve {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P521():
		return "P-521", 66, nil
	default:
		return "", 0, errors.New("unsupported ec curve")
	}
}

func bigIntToFixedBytes(v *big.Int, size int) []byte {
	if v == nil {
		return make([]byte, size)
	}
	b := v.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

type protectedHeader struct {
	Alg string     `json:"alg"`
	Enc string     `json:"enc"`
	EPK *epkHeader `json:"epk,omitempty"`
}

type epkHeader struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func rsaAlgFromJWK(v string) (jose.KeyAlgorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "RSA-OAEP-256":
		return jose.RSA_OAEP_256, nil
	default:
		return "", errors.Errorf("unsupported rsa jwk alg %q", v)
	}
}

func ecAlgFromJWK(v string) (jose.KeyAlgorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	default:
		return "", errors.Errorf("unsupported ec jwk alg %q", v)
	}
}

func rsaPublicKeyFromJWK(jwk *model.JWK) (*rsa.PublicKey, error) {
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

	// imposing lower limit on the size of the public key for enhanced security reasons
	if n.BitLen() <= 2048 {
		return nil, errors.New("RSA key size must be greater than 2048 bits")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func ecPublicKeyFromJWK(jwk *model.JWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-521":
		curve = elliptic.P521()
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
	byteLen := (curve.Params().BitSize + 7) / 8

	// Allocate a single slice for the uncompressed key: 1 byte prefix + X + Y
	uncompressedBytes := make([]byte, 1+byteLen*2)

	// Set the SEC 1 uncompressed format prefix
	uncompressedBytes[0] = 0x04

	// Copy X and Y bytes into their respective padded positions
	copy(uncompressedBytes[1:1+byteLen], xBytes)
	copy(uncompressedBytes[1+byteLen:1+byteLen*2], yBytes)

	// Parse using the recommended API
	public, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressedBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse public key")
	}

	return public, nil
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
