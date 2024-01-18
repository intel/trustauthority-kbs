/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package http

import (
	"fmt"
	"intel/kbs/v1/constant"
	"net/url"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

var (
	idReg              = fmt.Sprintf("{id:%s}", constant.UUIDReg)
	stringReg          = regexp.MustCompile("(^[a-zA-Z0-9_ \\/.-]*$)")
	sha256HexStringReg = regexp.MustCompile("^[a-fA-F0-9]{64}$")
	sha384HexStringReg = regexp.MustCompile("^[a-fA-F0-9]{96}$")
)

// ValidateStrings method is used to validate input strings
func ValidateStrings(strings []string) error {
	for _, stringValue := range strings {
		if !stringReg.MatchString(stringValue) {
			return errors.New("Invalid string formatted input")
		}
	}
	return nil
}

// ValidateSha256HexString method checks if a string is a valid hex string of 32 bytes
func ValidateSha256HexString(value string) error {
	in := strings.TrimSpace(value)
	if in == "" || !sha256HexStringReg.MatchString(in) {
		return errors.New("invalid SHA256 hex string format")
	}
	return nil
}

// ValidateSha384HexString method checks if a string is a valid hex string of 48 bytes
func ValidateSha384HexString(value string) error {
	in := strings.TrimSpace(value)
	if in == "" || !sha384HexStringReg.MatchString(value) {
		return errors.New("invalid SHA384 hex string format")
	}
	return nil
}

func ValidateQueryParamKeys(params url.Values, validQueries map[string]bool) error {
	if len(params) == 0 {
		return ErrInvalidQueryParam
	}
	if len(params) > constant.MaxQueryParamsLength {
		return ErrTooManyQueryParams
	}
	for param := range params {
		if _, hasQuery := validQueries[param]; !hasQuery {
			return ErrInvalidQueryParam
		}
	}
	return nil
}
