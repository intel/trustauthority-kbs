/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"github.com/google/uuid"
	"time"
)

type UserInfo struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
	Username     string    `json:"username"`
	PasswordHash []byte    `json:"password_hash"`
	PasswordCost int       `json:"password_cost"`
	Permissions  []string  `json:"permissions"`
}

type UserResponse struct {
	// Universal Unique IDentifier of the user
	// example: 8170574b-a783-4357-747f-3e52922f2ed8
	ID uuid.UUID `json:"id"`
	// Asset creation time
	// example: 0001-01-01T00:00:00Z
	CreatedAt time.Time `json:"created_at,omitempty"`
	// Asset modification time
	// example: 0001-01-01T00:00:00Z
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Specified Username for whom User ID is created
	// example: testUser
	Username string `json:"username"`
	// Roles associated with an user
	// example: [ "users:create", "users:search" ]
	Permissions []string `json:"permissions"`
}

type User struct {
	// required: true
	// example: testUser
	Username string `json:"username"`
	// required: true
	// example: testPassword
	Password string `json:"password"`
	// Roles associated with an user
	// required: true
	// example: [ "users:create", "users:search" ]
	Permissions []string `json:"permissions"`
}

type UpdateUserRequest struct {
	ID         uuid.UUID
	UpdateUser *User
}

type UserFilterCriteria struct {
	Username string
}
