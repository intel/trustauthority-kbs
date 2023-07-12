/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package jwt

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"intel/amber/kbs/v1/constant"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"intel/amber/kbs/v1/clients"
	"intel/amber/kbs/v1/crypt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

		certHash, err := crypt.GetCertHashInHex(cert, crypto.SHA384)
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

// Function to get CRL Object from CRL URL
func GetCRL(crlArr []string) (*x509.RevocationList, error) {

	if len(crlArr) < 1 {
		return nil, errors.New("Invalid CRL count present in the certificate")
	}

	crl, err := url.Parse(crlArr[0])
	if err != nil {
		return nil, errors.Wrap(err, "Invalid CRL URL")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, // keeping TLS1.2 for compatibility with AWSGW
				ServerName: crl.Hostname(),
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}

	var crlObj *x509.RevocationList

	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, crlArr[0], nil)
	}
	processResponse := func(resp *http.Response) error {
		crlPem, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", crlArr[0], err)
		}

		crlObj, err = x509.ParseRevocationList([]byte(crlPem))
		if err != nil {
			return errors.Wrap(err, "Failed to parse revocation list")
		}
		return nil
	}

	if err := clients.RequestAndProcessResponse(client, newRequest, nil, nil, processResponse); err != nil {
		return nil, err
	}
	return crlObj, nil
}

// Function to verify the Certificate against CRL
func verifyCRL(crl *x509.RevocationList, leafCert *x509.Certificate, caCert *x509.Certificate) error {
	if leafCert == nil || caCert == nil || crl == nil {
		return errors.New("Leaf Cert or caCert or CRL is nil")
	}

	//Checking CRL signed by CA Certificate
	err := crl.CheckSignatureFrom(caCert)
	if err != nil {
		return errors.Wrap(err, "CRL signature verification failed")
	}

	if crl.NextUpdate.Before(time.Now()) {
		return errors.New("CRL not valid, outdated CRL")
	}

	for _, rCert := range crl.RevokedCertificates {
		if rCert.SerialNumber.Cmp(leafCert.SerialNumber) == 0 {
			return errors.New("Certificate already Revoked")
		}
	}
	return nil
}

func (v *verifierPrivate) ValidateTokenAndGetClaims(tokenString string, customClaims interface{}) (*Token, error) {

	token := Token{}
	token.standardClaims = &jwt.StandardClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, token.standardClaims, func(token *jwt.Token) (interface{}, error) {
		var kid string
		keyIDValue, keyIDExists := token.Header["kid"]
		if !keyIDExists {
			return nil, fmt.Errorf("kid field missing in token header")
		} else {
			var ok bool
			kid, ok = keyIDValue.(string)
			if !ok {
				return nil, fmt.Errorf("kid field in jwt header is not valid : %v", kid)
			}
		}

		jkuValue, jkuExists := token.Header["jku"]
		if !jkuExists {
			return nil, fmt.Errorf("jku field missing in token header")
		}

		tokenSignCertUrl, ok := jkuValue.(string)
		if !ok {
			return nil, fmt.Errorf("jku in jwt header is not a valid string: %v", tokenSignCertUrl)
		}

		log.Debugf("Token signing url:%s", tokenSignCertUrl)
		jku, err := url.Parse(tokenSignCertUrl)
		if err != nil {
			return nil, fmt.Errorf("malformed URL provided for Token Signing Cert download")
		}

		newRequest := func() (*http.Request, error) {
			return http.NewRequest(http.MethodGet, tokenSignCertUrl, nil)
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12, // keeping TLS1.2 for compatibility with AWSGW
					ServerName: jku.Hostname(),
				},
				Proxy: http.ProxyFromEnvironment,
			},
		}

		var headers = map[string]string{
			"Accept": "application/json",
		}

		var pubKey interface{}
		var leafCert *x509.Certificate
		var interCACert *x509.Certificate
		var rootCert *x509.Certificate

		processResponse := func(resp *http.Response) error {
			jwks, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("Failed to read body from %s: %s", tokenSignCertUrl, err)
			}
			jwkSet, err := jwk.Parse(jwks)
			if err != nil {
				return fmt.Errorf("Unable to unmarshal response into a JWT Key Set")
			}

			jwkKey, found := jwkSet.LookupKeyID(kid)
			if !found {
				return fmt.Errorf("Could not find Key matching the key id")
			}
			atsCerts := jwkKey.X509CertChain()

			if atsCerts.Len() > constant.AtsCertChainMaxLen {
				return errors.Errorf("Token Signing Cert chain has more than %d certificates", constant.AtsCertChainMaxLen)
			}

			root := x509.NewCertPool()
			intermediate := x509.NewCertPool()

			for i := 0; i < atsCerts.Len(); i++ {
				atsCert, ok := atsCerts.Get(i)
				if !ok {
					return errors.Errorf("Failed to fetch certificate at index %d", i)
				}

				cer, err := cert.Parse(atsCert)
				if err != nil {
					return errors.Errorf("Failed to parse x509 certificate[%d]: %v", i, err)
				}

				if cer.IsCA && cer.BasicConstraintsValid && strings.Contains(cer.Subject.CommonName, "Root CA") {
					root.AddCert(cer)
					rootCert = cer
				} else if strings.Contains(cer.Subject.CommonName, "Signing CA") {
					intermediate.AddCert(cer)
					interCACert = cer
				} else {
					leafCert = cer
				}
			}
			opts := x509.VerifyOptions{
				Roots:         root,
				Intermediates: intermediate,
			}

			if _, err := leafCert.Verify(opts); err != nil {
				return fmt.Errorf("Failed to verify cert chain: %v", err.Error())
			}

			err = jwkKey.Raw(&pubKey)
			if err != nil {
				return fmt.Errorf("Failed to extract Public Key from Certificate")
			}
			return nil
		}

		if err := clients.RequestAndProcessResponse(client, newRequest, nil, headers, processResponse); err != nil {
			return nil, err
		}

		rootCrl, err := GetCRL(interCACert.CRLDistributionPoints)
		if err != nil {
			return nil, errors.Errorf("Failed to get ROOT CA CRL Object: %v", err.Error())
		}

		if err = verifyCRL(rootCrl, interCACert, rootCert); err != nil {
			return nil, errors.Errorf("Failed to check ATS CA Certificate against Root CA CRL: %v", err.Error())
		}

		atsCrl, err := GetCRL(leafCert.CRLDistributionPoints)
		if err != nil {
			return nil, errors.Errorf("Failed to get ATS CRL Object: %v", err.Error())
		}

		if err = verifyCRL(atsCrl, leafCert, interCACert); err != nil {
			return nil, errors.Errorf("Failed to check ATS Leaf certificate against ATS CRL: %v", err.Error())
		}
		return pubKey, nil

	})
	if err != nil {
		return nil, fmt.Errorf("Error in ParseWithClaims:%s", err)
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
	if err != nil {
		return nil, fmt.Errorf("failed to decode token claims as json")
	}
	token.customClaims = customClaims

	return &token, nil
}
