/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestZeroizeByteArray(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	ZeroizeByteArray(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %d", i, b)
		}
	}
}

func TestZeroizeBigInt(t *testing.T) {
	value := big.NewInt(12345)
	ZeroizeBigInt(value)

	if value.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Big int is not zero after zeroization: %v", value)
	}
}

func TestZeroizeRSAPrivateKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ZeroizeRSAPrivateKey(privateKey)

	if privateKey.D.Cmp(big.NewInt(0)) != 0 {
		t.Error("Private key D is not zero after zeroization")
	}

	for i, prime := range privateKey.Primes {
		if prime.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("Prime %d is not zero after zeroization", i)
		}
	}
}

func TestZeroizeECDSAPrivateKey(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ZeroizeECDSAPrivateKey(privateKey)

	if privateKey.D.Cmp(big.NewInt(0)) != 0 {
		t.Error("Private key D is not zero after zeroization")
	}
}
