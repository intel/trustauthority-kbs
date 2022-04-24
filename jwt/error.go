/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package jwt

import (
	"fmt"
)

type MatchingCertNotFoundError struct {
	KeyId string
}

func (e MatchingCertNotFoundError) Error() string {
	return fmt.Sprintf("certificate with matching public key not found. kid (key id) : %s", e.KeyId)
}

type MatchingCertJustExpired struct {
	KeyId string
}

func (e MatchingCertJustExpired) Error() string {
	return fmt.Sprintf("certificate with matching public key just expired. kid (key id) : %s", e.KeyId)
}
