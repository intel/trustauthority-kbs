/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
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
