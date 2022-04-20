/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"intel/amber/kbs/v1/clients"
	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/crypt"
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

	asBaseUrl, err := url.Parse(configuration.ASBaseUrl)
	if err != nil {
		log.WithError(err).Error("Error parsing APS url")
		return err
	}

	// Load trusted CA certificates
	caCerts, err := crypt.GetCertsFromDir(constant.TrustedCaCertsDir)
	if err != nil {
		log.WithError(err).Error("Error loading CA certificates")
		return err
	}

	// Initialize the APS client
	client := clients.HTTPClientWithCA(caCerts)
	asClient := as.NewASClient(client, asBaseUrl, configuration.ASApiKey)

	// Create repository layer and remote manager
	repository := repository.NewDirectoryRepository(constant.HomeDir)
	remoteManager := keymanager.NewRemoteManager(repository.KeyStore, keyManager)

	svc, err := service.NewService(asClient, repository, remoteManager)
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
