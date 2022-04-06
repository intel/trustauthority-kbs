/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/service"

	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func InitHTTPHandlers(svc service.Service, conf *config.Configuration) (http.Handler, error) {
	r := mux.NewRouter()
	r.SkipClean(true)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	{
		prefix := r.PathPrefix(fmt.Sprintf("/%s/%s", constant.ServiceName, constant.ApiVersion))
		sr := prefix.Subrouter()

		myHandlers := []func(service.Service, *mux.Router, []httpTransport.ServerOption) error{
			setGetVersionHandler,
			setKeyHandler,
			setKeyTransferPolicyHandler,
			setKeyTransferHandler,
		}

		for _, handler := range myHandlers {
			if err := handler(svc, sr, options); err != nil {
				return nil, err
			}
		}
	}

	h := handlers.RecoveryHandler(
		handlers.RecoveryLogger(log.StandardLogger()),
		handlers.PrintRecoveryStack(true),
	)(
		handlers.CombinedLoggingHandler(
			log.StandardLogger().Writer(),
			r,
		),
	)

	return h, nil
}

func encodeJsonResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if response != nil {
		// Send JSON response back to the client application
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			log.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
			return err
		}
	}

	return nil
}

func errorEncoder(_ context.Context, err error, w http.ResponseWriter) {
	if handledError, ok := err.(*service.HandledError); ok {
		w.WriteHeader(handledError.Code)
	} else {
		w.WriteHeader(errToCode(err))
	}
	if err := json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()}); err != nil {
		log.WithError(err).Error("Failed to encode error")
	}
}

func errorDecoder(r *http.Response) error {
	var w errorWrapper
	if err := json.NewDecoder(r.Body).Decode(&w); err != nil {
		return err
	}
	return errors.New(w.Error)
}

func errToCode(err error) int {
	switch err {
	case ErrInvalidRequest, ErrJsonDecodeFailed, ErrEmptyRequestBody, ErrTooManyQueryParams, ErrInvalidQueryParam, ErrInvalidFilterCriteria, ErrBase64DecodeFailed:
		return http.StatusBadRequest
	case ErrInvalidContentTypeHeader, ErrInvalidAcceptHeader:
		return http.StatusUnsupportedMediaType
	}
	return http.StatusInternalServerError
}

type errorWrapper struct {
	Error string `json:"error"`
}
