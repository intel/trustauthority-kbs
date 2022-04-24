/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"intel/amber/kbs/v1/clients"
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
	log.Infof("configuration: %v", configuration)
	if configuration == nil {
		return errors.New("Failed to load configuration")
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
	asClient, err := initASClient(configuration)
	if err != nil {
		return err
	}

	// Initialize JwtVerifier
	var cacheTime, _ = time.ParseDuration(constant.JWTCertsCacheTime)
	jwtVerifier, err := initJwtVerifier(constant.TrustedJWTSigningCertsDir, constant.TrustedCACertsDir, cacheTime)
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

	// Associate the service to rest endpoints/http
	httpHandlers, err := httpTransport.InitHTTPHandlers(svc, configuration)
	if err != nil {
		return errors.Wrap(err, "Failed to initialize HTTP handlers")
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", configuration.ServicePort),
		Handler: httpHandlers,
	}

	// Dispatch web server go routine
	log.Info("Starting server")
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.WithError(err).Fatal("Failed to start HTTP server")
			}
			stop <- syscall.SIGTERM
		}
	}()

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

func initASClient(cfg *config.Configuration) (as.ASClient, error) {

	asBaseUrl, err := url.Parse(cfg.ASBaseUrl)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing AS url")
	}

	caCerts, err := crypt.GetCertsFromDir(constant.TrustedCACertsDir)
	if err != nil {
		return nil, errors.Wrap(err, "Error loading CA certificates")
	}

	client := clients.HTTPClientWithCA(caCerts)
	asClient := as.NewASClient(client, asBaseUrl, cfg.ASApiKey)

	return asClient, nil
}

func initJwtVerifier(signingCertsDir, trustedCAsDir string, cacheTime time.Duration) (jwt.Verifier, error) {

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
		if matched, _ := path.Match(pattern, info.Name()); matched == true {
			if content, err := ioutil.ReadFile(fPath); err == nil {
				dirContents = append(dirContents, content)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(dirContents) == 0 {
		return nil, fmt.Errorf("no files found with matching pattern %s under directory %s", pattern, dir)
	}
	return dirContents, nil
}
