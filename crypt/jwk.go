/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"intel/kbs/v1/model"

	"github.com/pkg/errors"
)

func ParseJWKPublicKey(jwk model.JWK) (crypto.PublicKey, error) {
	if err := jwk.Validate(); err != nil {
		return nil, err
	}

	if jwk.IsRSA() {
		return parseRSAPublicKey(jwk)
	}

	if jwk.IsEC() {
		return parseECPublicKey(jwk)
	}

	return nil, errors.Errorf("unsupported jwk kty %q", jwk.Kty)
}

func parseRSAPublicKey(jwk model.JWK) (*rsa.PublicKey, error) {
	n, err := decodeBase64URLBigInt(jwk.N)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode rsa modulus n")
	}
	eBig, err := decodeBase64URLBigInt(jwk.E)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode rsa exponent e")
	}
	if !eBig.IsInt64() {
		return nil, errors.New("rsa exponent e is too large")
	}
	e := int(eBig.Int64())
	if e <= 0 {
		return nil, errors.New("rsa exponent e must be positive")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseECPublicKey(jwk model.JWK) (*ecdsa.PublicKey, error) {
	curve, err := ecCurveFromName(jwk.Crv)
	if err != nil {
		return nil, err
	}

	x, err := decodeBase64URLBigInt(jwk.X)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode ec x coordinate")
	}
	y, err := decodeBase64URLBigInt(jwk.Y)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode ec y coordinate")
	}

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("ec key point is not on curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func ecCurveFromName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, errors.Errorf("unsupported ec curve %q", name)
	}
}

func decodeBase64URLBigInt(v string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	out := new(big.Int).SetBytes(raw)
	if out.Sign() == 0 {
		return nil, errors.New("decoded integer cannot be zero")
	}
	return out, nil
}
