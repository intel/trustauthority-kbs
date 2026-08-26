/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sort"
	"testing"

	"intel/kbs/v1/model"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
)

func TestEncryptResourceAsFlattenedJWE_RSA_GuestCompat(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	pubJWK := &model.JWK{
		Kty: "RSA",
		Alg: "RSA-OAEP-256",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}

	plaintext := []byte("trustee-rsa-interop")
	jwe, err := encryptResourceAsFlattenedJWE(pubJWK, plaintext)
	if err != nil {
		t.Fatalf("encrypt jwe: %v", err)
	}

	decrypted, err := decryptLikeGuestComponents(jwe, priv, nil)
	if err != nil {
		t.Fatalf("guest-compatible decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, plaintext)
	}
}

func TestEncryptResourceAsFlattenedJWE_EC_GuestCompat(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}

	pubJWK := &model.JWK{
		Kty: "EC",
		Alg: "ECDH-ES+A256KW",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(bigIntToFixedBytes(priv.PublicKey.X, 32)),
		Y:   base64.RawURLEncoding.EncodeToString(bigIntToFixedBytes(priv.PublicKey.Y, 32)),
	}

	plaintext := []byte("trustee-ec-interop")
	jwe, err := encryptResourceAsFlattenedJWE(pubJWK, plaintext)
	if err != nil {
		t.Fatalf("encrypt jwe: %v", err)
	}

	protected := map[string]any{}
	protectedRaw, err := base64.RawURLEncoding.DecodeString(jwe.Protected)
	if err != nil {
		t.Fatalf("decode protected: %v", err)
	}
	if err := json.Unmarshal(protectedRaw, &protected); err != nil {
		t.Fatalf("unmarshal protected: %v", err)
	}
	if _, ok := protected["apu"]; ok {
		t.Fatalf("unexpected apu in protected header")
	}
	if _, ok := protected["apv"]; ok {
		t.Fatalf("unexpected apv in protected header")
	}

	decrypted, err := decryptLikeGuestComponents(jwe, nil, priv)
	if err != nil {
		t.Fatalf("guest-compatible decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, plaintext)
	}
}

func decryptLikeGuestComponents(jwe *model.JWEFlattened, rsaPriv *rsa.PrivateKey, ecPriv *ecdsa.PrivateKey) ([]byte, error) {
	protectedRaw, err := base64.RawURLEncoding.DecodeString(jwe.Protected)
	if err != nil {
		return nil, err
	}

	protectedMap := map[string]any{}
	if err := json.Unmarshal(protectedRaw, &protectedMap); err != nil {
		return nil, err
	}

	alg, _ := protectedMap["alg"].(string)
	enc, _ := protectedMap["enc"].(string)
	if enc != "A256GCM" {
		return nil, errString("unsupported enc")
	}

	encryptedKey, err := base64.RawURLEncoding.DecodeString(jwe.EncryptedKey)
	if err != nil {
		return nil, err
	}

	var cek []byte
	switch alg {
	case "RSA-OAEP-256":
		cek, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, encryptedKey, nil)
		if err != nil {
			return nil, err
		}
	case "ECDH-ES+A256KW":
		epkAny, ok := protectedMap["epk"]
		if !ok {
			return nil, errString("missing epk")
		}
		epkMap, ok := epkAny.(map[string]any)
		if !ok {
			return nil, errString("invalid epk")
		}
		xs, _ := epkMap["x"].(string)
		ys, _ := epkMap["y"].(string)
		xBytes, err := base64.RawURLEncoding.DecodeString(xs)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(ys)
		if err != nil {
			return nil, err
		}
		ephemeralPub := &ecdsa.PublicKey{Curve: ecPriv.Curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
		kek := josecipher.DeriveECDHES("ECDH-ES+A256KW", []byte{}, []byte{}, ecPriv, ephemeralPub, 32)
		block, err := aes.NewCipher(kek)
		if err != nil {
			return nil, err
		}
		cek, err = josecipher.KeyUnwrap(block, encryptedKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errString("unsupported alg")
	}

	aad, err := generateAADLikeKbsTypes(protectedRaw)
	if err != nil {
		return nil, err
	}

	iv, err := base64.RawURLEncoding.DecodeString(jwe.IV)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(jwe.Ciphertext)
	if err != nil {
		return nil, err
	}
	tag, err := base64.RawURLEncoding.DecodeString(jwe.Tag)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := append(ciphertext, tag...)
	return gcm.Open(nil, iv, sealed, aad)
}

func generateAADLikeKbsTypes(protectedRaw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(protectedRaw, &v); err != nil {
		return nil, err
	}
	canonical, err := marshalCanonicalJSON(v)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(canonical)
	return []byte(encoded), nil
}

func marshalCanonicalJSON(v any) ([]byte, error) {
	switch tv := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(tv))
		for k := range tv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			vb, err := marshalCanonicalJSON(tv[k])
			if err != nil {
				return nil, err
			}
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, kb...)
			out = append(out, ':')
			out = append(out, vb...)
		}
		out = append(out, '}')
		return out, nil
	case []any:
		out := []byte{'['}
		for i := range tv {
			vb, err := marshalCanonicalJSON(tv[i])
			if err != nil {
				return nil, err
			}
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, vb...)
		}
		out = append(out, ']')
		return out, nil
	default:
		return json.Marshal(tv)
	}
}

type errString string

func (e errString) Error() string {
	return string(e)
}
