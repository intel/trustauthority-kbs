/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */

package http

import (
	"context"
	"encoding/json"
	"github.com/go-kit/kit/endpoint"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"intel/kbs/v1/config"
	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"intel/kbs/v1/service"
	"net/http"
	"strings"
)

const (
	Username = "username"
)

var (
	allowedAPIs           = map[string]bool{"users": true, "keys": true, "key-transfer-policies": true}
	allowedAPIPermissions = map[string]bool{"create": true, "delete": true, "search": true, "update": true, "transfer": true}
)

func setUserHandler(svc service.Service, router *mux.Router, options []httpTransport.ServerOption, auth *model.JwtAuthz) error {

	userIdExpr := "/users/" + idReg
	createUserHandler := httpTransport.NewServer(
		makeCreateUserEndpoint(svc),
		decodeCreateUserHTTPRequest,
		encodeCreateUserHTTPResponse,
		options...,
	)

	router.Handle("/users", authMiddleware(createUserHandler, auth)).Methods(http.MethodPost)

	getUserHandler := httpTransport.NewServer(
		makeRetrieveUserEndpoint(svc),
		decodeRetrieveHTTPRequest,
		encodeRetrieveHTTPResponse,
		options...,
	)

	router.Handle(userIdExpr, authMiddleware(getUserHandler, auth)).Methods(http.MethodGet)

	deleteUserHandler := httpTransport.NewServer(
		makeDeleteUserEndpoint(svc),
		decodeDeleteHTTPRequest,
		encodeDeleteHTTPResponse,
		options...,
	)

	router.Handle(userIdExpr, authMiddleware(deleteUserHandler, auth)).Methods(http.MethodDelete)

	searchUserHandler := httpTransport.NewServer(
		makeSearchUserEndpoint(svc),
		decodeSearchUserHTTPRequest,
		encodeSearchUserHTTPResponse,
		options...,
	)

	router.Handle("/users", authMiddleware(searchUserHandler, auth)).Methods(http.MethodGet)

	updateUserHandler := httpTransport.NewServer(
		makeUpdateUserEndpoint(svc),
		decodeUpdateUserHTTPRequest,
		encodeCreateUserHTTPResponse,
		options...,
	)

	router.Handle(userIdExpr, authMiddleware(updateUserHandler, auth)).Methods(http.MethodPut)

	return nil
}

func makeCreateUserEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*model.User)
		return svc.CreateUser(ctx, req)
	}
}

func makeUpdateUserEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*model.UpdateUserRequest)
		return svc.UpdateUser(ctx, req)
	}
}

func makeSearchUserEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		filter := request.(*model.UserFilterCriteria)
		return svc.SearchUser(ctx, filter)
	}
}

func makeDeleteUserEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		id := request.(uuid.UUID)
		return svc.DeleteUser(ctx, id)
	}
}

func makeRetrieveUserEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		id := request.(uuid.UUID)
		return svc.RetrieveUser(ctx, id)
	}
}

func decodeCreateUserHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	if r.Header.Get(constant.HTTPHeaderKeyContentType) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidContentTypeHeader.Error())
		return nil, ErrInvalidContentTypeHeader
	}

	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}

	if r.ContentLength == 0 {
		log.Error(ErrEmptyRequestBody.Error())
		return nil, ErrEmptyRequestBody
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var userCreateReq *model.User
	err := dec.Decode(&userCreateReq)
	if err != nil {
		log.WithError(err).Error(ErrJsonDecodeFailed.Error())
		return nil, ErrJsonDecodeFailed
	}

	// validate username
	if err = config.ValidateUsername(userCreateReq.Username); err != nil {
		log.Error("Invalid input for username")
		return nil, ErrInvalidRequest
	}

	//validate password
	if err = config.ValidatePassword(userCreateReq.Password); err != nil {
		log.Error("Invalid input for password")
		return nil, ErrInvalidRequest
	}

	if len(userCreateReq.Permissions) == 0 {
		log.Error("Invalid input for permissions")
		return nil, ErrInvalidRequest
	} else {
		// checking for valid API's and crud permissions
		err := validateUserPermissions(userCreateReq.Permissions)
		if err != nil {
			return nil, err
		}
	}

	return userCreateReq, nil
}

func decodeUpdateUserHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}
	if r.Header.Get(constant.HTTPHeaderKeyContentType) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidContentTypeHeader.Error())
		return nil, ErrInvalidContentTypeHeader
	}

	if r.ContentLength == 0 {
		log.Error(ErrEmptyRequestBody.Error())
		return nil, ErrEmptyRequestBody
	}

	id := uuid.MustParse(mux.Vars(r)["id"])
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var user model.User
	err := dec.Decode(&user)
	if err != nil {
		log.WithError(err).Error(ErrJsonDecodeFailed.Error())
		return nil, ErrJsonDecodeFailed
	}

	if user.Username != "" {
		if err = config.ValidateUsername(user.Username); err != nil {
			log.Error("Invalid input for username")
			return nil, ErrInvalidRequest
		}
	}
	if user.Password != "" {
		// validate password
		if err = config.ValidatePassword(user.Password); err != nil {
			log.Error("Invalid input for password")
			return nil, ErrInvalidRequest
		}
	}
	if len(user.Permissions) != 0 {
		err := validateUserPermissions(user.Permissions)
		if err != nil {
			return nil, err
		}
	}

	userUpdateReq := &model.UpdateUserRequest{
		ID:         id,
		UpdateUser: &user,
	}
	return userUpdateReq, nil
}

func decodeSearchUserHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}

	queryKeys := map[string]bool{
		Username: true,
	}

	queryValues := r.URL.Query()
	if err := ValidateQueryParamKeys(queryValues, queryKeys); err != nil {
		return nil, ErrInvalidQueryParam
	}

	criteria := model.UserFilterCriteria{}

	// username query
	if param := strings.TrimSpace(queryValues.Get(Username)); param != "" {
		if err := config.ValidateUsername(param); err != nil {
			log.WithError(err).Error(ErrInvalidFilterCriteria.Error())
			return nil, ErrInvalidFilterCriteria
		}
		criteria.Username = param
	}

	return &criteria, nil
}

func encodeCreateUserHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(*model.UserResponse)

	header := w.Header()
	header.Set(constant.HTTPHeaderKeyContentType, constant.HTTPHeaderValueApplicationJson)
	w.WriteHeader(http.StatusCreated)

	return encodeJsonResponse(ctx, w, resp)
}

func encodeSearchUserHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.([]model.UserResponse)

	header := w.Header()
	header.Set(constant.HTTPHeaderKeyContentType, constant.HTTPHeaderValueApplicationJson)
	w.WriteHeader(http.StatusOK)

	return encodeJsonResponse(ctx, w, resp)
}

func validateUserPermissions(permissions []string) error {
	for _, permission := range permissions {
		apiPerm := strings.Split(permission, ":")
		if len(apiPerm) != 2 {
			log.Error("Invalid input for permission format")
			return ErrInvalidRequest
		}
		if !allowedAPIs[apiPerm[0]] || !allowedAPIPermissions[apiPerm[1]] {
			log.Error("Invalid input for permission")
			return ErrInvalidRequest
		}
	}
	return nil
}
