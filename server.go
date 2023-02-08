/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/tasks"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	jwtStrategy "github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
	"github.com/shaj13/libcache"

	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/crypt"
	"intel/amber/kbs/v1/jwt"
	"intel/amber/kbs/v1/keymanager"
	"intel/amber/kbs/v1/repository"
	"intel/amber/kbs/v1/service"
	httpTransport "intel/amber/kbs/v1/transport/http"

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

	// Initialize AS client
	asClient, err := newASClient(configuration)
	if err != nil {
		return err
	}

	// Initialize JwtVerifier
	var cacheTime, _ = time.ParseDuration(constant.JWTCertsCacheTime)
	jwtVerifier, err := newJwtVerifier(constant.TrustedJWTSigningCertsDir, constant.TrustedCACertsDir, cacheTime)
	if err != nil {
		return err
	}

	// Initialize the Service
	svc, err := service.NewService(asClient, jwtVerifier, repository, remoteManager)
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

	jwtAuthZ, err := setupAuthZ()
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
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
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

func newASClient(cfg *config.Configuration) (as.ASClient, error) {

	asBaseUrl, err := url.Parse(cfg.ASBaseUrl)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing AS url")
	}

	caCerts, err := crypt.GetCertsFromDir(constant.TrustedCACertsDir)
	if err != nil {
		return nil, errors.Wrap(err, "Error loading CA certificates")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, // keeping TLS1.2 for compatibility with AWSGW
				RootCAs:    crypt.GetCertPool(caCerts),
				ServerName: asBaseUrl.Hostname(),
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}

	asClient := as.NewASClient(client, asBaseUrl, cfg.ASApiKey)

	return asClient, nil
}

func newJwtVerifier(signingCertsDir, trustedCAsDir string, cacheTime time.Duration) (jwt.Verifier, error) {

	certPems, err := GetDirFileContents(signingCertsDir, "*.pem")
	if err != nil {
		return nil, err
	}

	rootPems, err := GetDirFileContents(trustedCAsDir, "*.pem")
	if err != nil {
		return nil, err
	}

	return jwt.NewVerifier(certPems, rootPems, cacheTime)
}

func GetDirFileContents(dir, pattern string) ([][]byte, error) {
	dirContents := make([][]byte, 0)
	//if we are passed in an empty pattern, set pattern to * to match all files
	if pattern == "" {
		pattern = "*"
	}

	err := filepath.Walk(dir, func(fPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, _ := path.Match(pattern, info.Name()); matched {
			if content, err := ioutil.ReadFile(fPath); err == nil {
				dirContents = append(dirContents, content)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return dirContents, nil
}

func setupAuthZ() (*model.JwtAuthz, error) {
	var strategy auth.Strategy
	var keeper jwtStrategy.SecretsKeeper

	bytes, err := ioutil.ReadFile(constant.DefaultJWTSigningKeyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	signingKey := parseResult.(*rsa.PrivateKey)

	keeper = jwtStrategy.StaticSecret{
		ID:        "secret-id",
		Secret:    signingKey,
		Algorithm: jwtStrategy.PS384,
	}

	cache := libcache.FIFO.New(0)
	cache.SetTTL(time.Minute * 5)

	opt := token.SetScopes(token.NewScope(constant.KeyTransferPolicyCreate, "/key-transfer-policies", "POST"),
		token.NewScope(constant.KeyTransferPolicySearch, "/key-transfer-policies", "GET"),
		token.NewScope(constant.KeyTransferPolicyDelete, "/key-transfer-policies", "DELETE"),
		token.NewScope(constant.KeyCreate, "/keys", "POST"),
		token.NewScope(constant.KeySearch, "/keys", "GET"),
		token.NewScope(constant.KeyDelete, "/keys", "DELETE"),
		token.NewScope(constant.KeyTransfer, "/keys/"+constant.UUIDReg, "POST"),
		token.NewScope(constant.UserCreate, "/users", "POST"),
		token.NewScope(constant.UserSearch, "/users", "GET"),
		token.NewScope(constant.UserUpdate, "/users", "PUT"),
		token.NewScope(constant.UserDelete, "/users", "DELETE"))
	strategy = jwtStrategy.New(cache, keeper, opt)

	jwtAuth := model.JwtAuthz{
		JwtSecretKeeper: keeper,
		AuthZStrategy:   strategy,
	}
	return &jwtAuth, nil
}
