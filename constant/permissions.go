/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package constant

const (
	KeyCreate   = "keys:create"
	KeyDelete   = "keys:delete"
	KeySearch   = "keys:search"
	KeyTransfer = "keys:transfer"
	KeyUpdate   = "keys:update"

	KeyTransferPolicyCreate = "key_transfer_policies:create"
	KeyTransferPolicyDelete = "key_transfer_policies:delete"
	KeyTransferPolicySearch = "key_transfer_policies:search"

	UserCreate = "users:create"
	UserDelete = "users:delete"
	UserSearch = "users:search"
	UserUpdate = "users:update"
)

var AdminPermissions = []string{KeySearch, KeyCreate, KeyDelete, KeyTransfer, KeyUpdate, KeyTransferPolicyCreate, KeyTransferPolicySearch, KeyTransferPolicyDelete, UserDelete, UserSearch, UserCreate, UserUpdate}
