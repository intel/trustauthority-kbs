/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package kbs

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	jwtStrategy "github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	"intel/kbs/v1/clients/ita"
	"intel/kbs/v1/config"
	"intel/kbs/v1/tasks"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"intel/kbs/v1/constant"
	"intel/kbs/v1/keymanager"
	"intel/kbs/v1/repository"
	"intel/kbs/v1/service"
	httpTransport "intel/kbs/v1/transport/http"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (app *App) startServer() error {

	configuration := app.Config
	if configuration == nil {
		return errors.New("Failed to load configuration")
	}
	if err := configuration.Validate(); err != nil {
		return errors.Wrap(err, "Invalid configuration")
	}

	// Initialize log
	if err := app.configureLogs(); err != nil {
		return err
	}

	// Initialize KeyManager
	keyManager, err := keymanager.NewKeyManager(configuration)
	if err != nil {
		return err
	}

	// Create repository layer and remote manager
	repository := repository.NewDirectoryRepository(constant.HomeDir)
	remoteManager := keymanager.NewRemoteManager(repository.KeyStore, keyManager)

	itaApiServername, err := url.Parse(config.TrustAuthorityApiUrl)
	if err != nil {
		return errors.Wrap(err, "Error parsing Trust Authority API url")
	}

	// initialize ITA client
	itaApiClient, err := ita.NewITAClient(configuration, itaApiServername.Hostname())
	if err != nil {
		return errors.Wrap(err, "Failed to initialize TrustAuthority Client")
	}

	// initialize ITA client for token verification
	itaTokenVerifierServername, err := url.Parse(config.TrustAuthorityBaseUrl)
	if err != nil {
		return errors.Wrap(err, "Error parsing Trust Authority Base url")
	}

	itaTokenVerifierClient, err := ita.NewITAClient(configuration, itaTokenVerifierServername.Hostname())
	if err != nil {
		return errors.Wrap(err, "Failed to initialize TrustAuthority Client for attestation token verification")
	}

	// Initialize the Service
	svc, err := service.NewService(itaApiClient, itaTokenVerifierClient, repository, remoteManager, configuration)
	if err != nil {
		msg := "Failed to initialize Service"
		log.WithError(err).Error(msg)
		return errors.New(msg)
	}

	if _, err := os.Stat(constant.DefaultJWTSigningKeyPath); errors.Is(err, os.ErrNotExist) {
		// create JWT signing key
		csk := tasks.CreateSigningKey{
			JWTSigningKeyPath: constant.DefaultJWTSigningKeyPath,
		}
		err := csk.CreateJWTSigningKey()
		if err != nil {
			log.WithError(err).Error("Error while creating JWT signing key")
			return err
		}
	}

	// initialize JWT authentication library
	bytes, err := os.ReadFile(constant.DefaultJWTSigningKeyPath)
	if err != nil {
		log.WithError(err).Error("Error while reading JWT signing key")
		return err
	}

	block, _ := pem.Decode(bytes)
	privKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	signingKey := privKey.(*rsa.PrivateKey)

	jwtKeeper := jwtStrategy.StaticSecret{
		ID:        "secret-id",
		Secret:    signingKey,
		Algorithm: jwtStrategy.PS384,
	}
	jwtAuthZ, err := service.SetupAuthZ(&jwtKeeper)
	if err != nil {
		return err
	}

	// Associate the service to rest endpoints/http
	httpHandlers, err := httpTransport.NewHTTPHandler(svc, configuration, jwtAuthZ)
	if err != nil {
		return errors.Wrap(err, "Failed to initialize HTTP handler")
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", configuration.ServicePort),
		Handler: httpHandlers,
	}

	// TLS support is enabled
	if _, err := os.Stat(constant.DefaultTLSCertPath); os.IsNotExist(err) {
		// TLS certificate and key does not exist, so creating the cert and key
		tlsKc := tasks.TLSKeyAndCert{
			TLSCertPath: constant.DefaultTLSCertPath,
			TLSKeyPath:  constant.DefaultTLSKeyPath,
			TlsSanList:  configuration.SanList,
		}
		err = tlsKc.GenerateTLSKeyandCert()
		if err != nil {
			return errors.Wrap(err, "Failed to generate TLS certificate and key")
		}
	}
	log.Debugf("Starting HTTPS server with TLS cert: %s", constant.DefaultTLSCertPath)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			// TLS_AES_128_CCM_SHA256 is not supported by go crypto/tls package
			tls.TLS_CHACHA20_POLY1305_SHA256},
	}
	httpServer.TLSConfig = tlsConfig

	// Dispatch web server go routine
	log.Info("Starting server")
	go func() {
		serveErr := httpServer.ListenAndServeTLS(constant.DefaultTLSCertPath, constant.DefaultTLSKeyPath)

		if serveErr != nil {
			if serveErr != http.ErrServerClosed {
				log.WithError(serveErr).Fatal("Failed to start HTTP server")
			}
			stop <- syscall.SIGTERM
		}
	}()

	// create an admin user
	ac := tasks.CreateAdminUser{
		AdminUsername: app.Config.AdminUsername,
		AdminPassword: app.Config.AdminPassword,
		UserStore:     repository.UserStore,
	}

	err = ac.CreateAdminUser()
	if err != nil {
		return err
	}

	log.Info("service started")
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Failed to gracefully shutdown webserver")
		return err
	}
	log.Info("service stopped")
	return nil
}
