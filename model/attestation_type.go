/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

type AttesterType string

const (
	TDX AttesterType = "TDX"
	SGX AttesterType = "SGX"
)

func (at AttesterType) String() string {
	return string(at)
}

func (at AttesterType) Valid() bool {
	switch at {
	case TDX, SGX:
		return true
	}
	return false
}
