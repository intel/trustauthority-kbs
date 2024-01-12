/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package kmipclient

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"

	"intel/kbs/v1/constant"

	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type KmipClient interface {
	InitializeClient(string, string, string, string, string, string, string, string, string) error
	CreateSymmetricKey(int) (string, error)
	CreateAsymmetricKeyPair(string, string, int) (string, error)
	DeleteKey(string) error
	GetKey(string, string) ([]byte, error)
	SendRequest(interface{}, kmip14.Operation) (*kmip.ResponseBatchItem, *ttlv.Decoder, error)
}

type kmipClient struct {
	KMIPVersion   string
	Config        tls.Config
	requestHeader kmip.RequestHeader
	ServerIP      string
	ServerPort    string
}

func NewKmipClient() KmipClient {
	return &kmipClient{}
}

var cipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA256}

// InitializeClient initializes all the values required for establishing connection to kmip server
func (kc *kmipClient) InitializeClient(version, serverIP, serverPort, hostname, username, password, clientKeyFilePath, clientCertificateFilePath, rootCertificateFilePath string) error {

	if (version != constant.KMIP14) && (version != constant.KMIP20) {
		return errors.Errorf("kmipclient/kmipclient:InitializeClient()Invalid Kmip version %s provided", version)
	}
	kc.KMIPVersion = version

	if serverIP == "" {
		return errors.New("kmipclient/kmipclient:InitializeClient() KMIP server address is not provided")
	}
	kc.ServerIP = serverIP

	if serverPort == "" {
		return errors.New("kmipclient/kmipclient:InitializeClient() KMIP server port is not provided")
	}
	kc.ServerPort = serverPort

	if clientCertificateFilePath == "" {
		return errors.New("kmipclient/kmipclient:InitializeClient() KMIP client certificate is not provided")
	}

	if clientKeyFilePath == "" {
		return errors.New("kmipclient/kmipclient:InitializeClient() KMIP client key is not provided")
	}

	if rootCertificateFilePath == "" {
		return errors.New("kmipclient/kmipclient:InitializeClient() KMIP root certificate is not provided")
	}

	protocolVersion := kmip.ProtocolVersion{}
	if kc.KMIPVersion == constant.KMIP20 {
		protocolVersion.ProtocolVersionMajor = 2
		protocolVersion.ProtocolVersionMinor = 0
	} else {
		protocolVersion.ProtocolVersionMajor = 1
		protocolVersion.ProtocolVersionMinor = 4
	}

	kc.requestHeader.ProtocolVersion = protocolVersion
	kc.requestHeader.BatchCount = 1

	if username != "" && password != "" {
		credential := kmip.Credential{}

		credential.CredentialType = kmip14.CredentialTypeUsernameAndPassword
		credential.CredentialValue = kmip.UsernameAndPasswordCredentialValue{
			Username: username,
			Password: password,
		}
		kc.requestHeader.Authentication = &kmip.Authentication{
			Credential: []kmip.Credential{
				credential,
			},
		}
		log.Info("kmipclient/kmipclient:InitializeClient() KMIP authentication with credential type UsernameAndPassword is added")
	}

	caCertificate, err := os.ReadFile(filepath.Clean(rootCertificateFilePath))
	if err != nil {
		return errors.Wrap(err, "kmipclient/kmipclient:InitializeClient() Unable to read root certificate")
	}
	log.Debugf("kmipclient/kmipclient:InitializeClient() Loaded root certificate from %s", rootCertificateFilePath)

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caCertificate)
	certificate, err := tls.LoadX509KeyPair(clientCertificateFilePath, clientKeyFilePath)
	if err != nil {
		return errors.Wrap(err, "kmipclient/kmipclient:InitializeClient() Failed to load client key and certificate")
	}
	log.Debugf("kmipclient/kmipclient:InitializeClient() Loaded client certificate from %s", clientCertificateFilePath)
	log.Debugf("kmipclient/kmipclient:InitializeClient() Loaded client key from %s", clientKeyFilePath)

	if hostname == "" {
		hostname = kc.ServerIP
	}

	kc.Config = tls.Config{
		ServerName:               hostname,
		CipherSuites:             cipherSuites,
		PreferServerCipherSuites: true,
		RootCAs:                  rootCAs,
		Certificates:             []tls.Certificate{certificate},
		MinVersion:               tls.VersionTLS12,
	}

	log.Info("kmipclient/kmipclient:InitializeClient() Kmip client initialized")
	return nil
}

// SendRequest perform send request message to kmip server and receive response messages
func (kc *kmipClient) SendRequest(requestPayload interface{}, Operation kmip14.Operation) (*kmip.ResponseBatchItem, *ttlv.Decoder, error) {

	conn, err := tls.Dial("tcp", kc.ServerIP+":"+kc.ServerPort, &kc.Config)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	_, err = conn.ConnectionState().PeerCertificates[0].Verify(x509.VerifyOptions{Roots: kc.Config.RootCAs})
	if err != nil {
		return nil, nil, err
	}

	message := kmip.RequestMessage{
		RequestHeader: kc.requestHeader,
		BatchItem: []kmip.RequestBatchItem{
			{
				Operation:      Operation,
				RequestPayload: requestPayload,
			},
		},
	}

	requestMessage, err := ttlv.Marshal(message)
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("kmipclient/kmipclient:SendRequest() Request Message for operation %s \n%s", Operation.String(), requestMessage)

	_, err = conn.Write(requestMessage)
	if err != nil {
		return nil, nil, err
	}

	decoder := ttlv.NewDecoder(bufio.NewReader(conn))
	response, err := decoder.NextTTLV()
	if err != nil {
		return nil, nil, err
	}

	var responseMessage kmip.ResponseMessage
	err = decoder.DecodeValue(&responseMessage, response)
	if err != nil {
		return nil, nil, err
	}

	responseTTLV, err := ttlv.Marshal(responseMessage)
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("kmipclient/kmipclient:SendRequest() Response Message for operation %s \n%s", Operation.String(), responseTTLV)

	if responseMessage.BatchItem[0].ResultStatus != kmip14.ResultStatusSuccess {
		return nil, nil, errors.Errorf("request message is failed with reason %s", responseMessage.BatchItem[0].ResultMessage)
	}
	log.Infof("kmipclient/kmipclient:SendRequest() The KMIP operation %s was executed with no errors", Operation.String())

	return &responseMessage.BatchItem[0], decoder, nil
}
