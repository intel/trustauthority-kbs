/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package jwt

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"intel/amber/kbs/v1/crypt"

	"github.com/golang-jwt/jwt"
)

type Verifier interface {
	ValidateTokenAndGetClaims(tokenString string, customClaims interface{}) (*Token, error)
}

type verifierKey struct {
	pubKey  crypto.PublicKey
	expTime time.Time
}

type verifierPrivate struct {
	expiration   time.Time
	pubKeyMapMtx sync.RWMutex
	pubKeyMap    map[string]verifierKey
}

func NewVerifier(signingCertPems interface{}, rootCAPems [][]byte, cacheTime time.Duration) (Verifier, error) {

	v := verifierPrivate{expiration: time.Now().Add(cacheTime)}
	v.pubKeyMap = make(map[string]verifierKey)

	var certPemSlice [][]byte

	switch signingCertPems.(type) {
	case nil:
		return &v, nil
	case [][]byte:
		certPemSlice = signingCertPems.([][]byte)
	case []byte:
		certPemSlice = [][]byte{signingCertPems.([]byte)}
	default:
		return nil, fmt.Errorf("signingCertPems has to be of type []byte or [][]byte")

	}
	// build the trust root CAs first
	roots := x509.NewCertPool()
	for _, rootPEM := range rootCAPems {
		roots.AppendCertsFromPEM(rootPEM)
	}

	verifyRootCAOpts := x509.VerifyOptions{
		Roots: roots,
	}

	for _, certPem := range certPemSlice {
		var cert *x509.Certificate
		var err error
		cert, verifyRootCAOpts.Intermediates, err = crypt.GetCertAndChainFromPem(certPem)
		if err != nil || time.Now().After(cert.NotAfter) { // expired certificate
			continue
		}

		// if certificate is not self signed, then we have to validate the cert
		// this implies that we are allowing self signed certificate.
		if !(cert.IsCA && cert.BasicConstraintsValid) {
			if _, err := cert.Verify(verifyRootCAOpts); err != nil {
				continue
			}
		}

		certHash, err := crypt.GetCertHashInHex(cert, crypto.SHA1)
		if err != nil {
			continue
		}
		pubKey, err := crypt.GetPublicKeyFromCert(cert)
		if err != nil {
			continue
		}
		v.pubKeyMapMtx.Lock()
		v.pubKeyMap[certHash] = verifierKey{pubKey: pubKey, expTime: cert.NotAfter}
		v.pubKeyMapMtx.Unlock()
		// update the validity of the object if the certificate expires before the current validity
		// TODO: set the expiration when based on CRL when it become available
		if v.expiration.After(cert.NotAfter) {
			v.expiration = cert.NotAfter
		}
	}
	// we will return a valid object at this point. it still might not contain any valid certificates
	return &v, nil

}

func (v *verifierPrivate) ValidateTokenAndGetClaims(tokenString string, customClaims interface{}) (*Token, error) {

	token := Token{}
	token.standardClaims = &jwt.StandardClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, token.standardClaims, func(token *jwt.Token) (interface{}, error) {

		if keyIDValue, keyIDExists := token.Header["kid"]; keyIDExists {

			keyIDString, ok := keyIDValue.(string)
			if !ok {
				return nil, fmt.Errorf("kid (key id) in jwt header is not a string : %v", keyIDValue)
			}

			v.pubKeyMapMtx.RLock()
			defer v.pubKeyMapMtx.RUnlock()
			if matchPubKey, found := v.pubKeyMap[keyIDString]; !found {
				return nil, &MatchingCertNotFoundError{keyIDString}
			} else {
				// if the certificate just expired.. we need to return appropriate error
				// so that the caller can deal with it appropriately
				now := time.Now()
				if now.After(matchPubKey.expTime) {
					return nil, &MatchingCertJustExpired{keyIDString}
				}
				return matchPubKey.pubKey, nil
			}

		} else {
			return nil, fmt.Errorf("kid (key id) field missing in token. field is mandatory")
		}
	})

	if err != nil {
		if jwtErr, ok := err.(*jwt.ValidationError); ok {
			switch e := jwtErr.Inner.(type) {
			case *MatchingCertNotFoundError, *MatchingCertJustExpired:
				return nil, e
			}
			return nil, jwtErr
		}
		return nil, err
	}
	token.jwtToken = parsedToken

	// so far we have only got the standardClaims parsed. We need to now fill the customClaims
	parts := strings.Split(tokenString, ".")

	// parse Claims
	var claimBytes []byte

	if claimBytes, err = jwt.DecodeSegment(parts[1]); err != nil {
		return nil, fmt.Errorf("could not decode claims part of the jwt token")
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	err = dec.Decode(customClaims)
	token.customClaims = customClaims

	return &token, nil
}
