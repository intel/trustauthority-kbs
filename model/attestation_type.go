/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package model

type AttestationType string

const (
	TDX AttestationType = "TDX"
	SGX AttestationType = "SGX"
)

func (at AttestationType) String() string {
	return string(at)
}

func (at AttestationType) Valid() bool {
	switch at {
	case TDX, SGX:
		return true
	}
	return false
}
