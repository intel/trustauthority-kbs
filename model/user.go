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
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	Username    string    `json:"username"`
	Permissions []string  `json:"permissions"`
}

type User struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	Permissions []string `json:"permissions"`
}

type UpdateUserRequest struct {
	ID         uuid.UUID
	UpdateUser *User
}

type UserFilterCriteria struct {
	Username string
}
