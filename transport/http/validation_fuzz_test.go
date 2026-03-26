/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

// Fuzz tests for HTTP transport input validation.
// Run with: go test ./transport/http -fuzz=FuzzValidate... -fuzztime=60s

package http

import (
	"net/url"
	"testing"
)

// FuzzValidateStrings exercises the string allow-list validator against
// arbitrary byte sequences.  Any panic indicates a correctness defect.
func FuzzValidateStrings(f *testing.F) {
	// Seed corpus: representative inputs including boundary and injection attempts
	seeds := []string{
		"",
		"hello world",
		"valid-string_123",
		"path/to/key",
		"../traversal",
		"'; DROP TABLE keys; --",
		"\x00\x01\x02",
		"<script>alert(1)</script>",
		"𝕳𝖊𝖑𝖑𝖔", // non-ASCII multibyte
		"A very long string " + string(make([]byte, 4096)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic regardless of input
		_ = ValidateStrings([]string{input})
	})
}

// FuzzValidateSha256HexString fuzzes the SHA-256 hex validator.
func FuzzValidateSha256HexString(f *testing.F) {
	seeds := []string{
		"",
		"ad46749ed41ebaa2327252041ee746d3791a9f2431830fee0883f7993caf316a",  // valid 64-char
		"ad46749ed41ebaa2327252041ee746d3791a9f2431830fee0883f7993caf316",   // 63 chars
		"ad46749ed41ebaa2327252041ee746d3791a9f2431830fee0883f7993caf316aa", // 65 chars
		"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",   // invalid hex
		"  ad46749ed41ebaa2327252041ee746d3791a9f2431830fee0883f7993caf316a ", // padded
		"\x00" + string(make([]byte, 63)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		_ = ValidateSha256HexString(input)
	})
}

// FuzzValidateSha384HexString fuzzes the SHA-384 hex validator.
func FuzzValidateSha384HexString(f *testing.F) {
	seeds := []string{
		"",
		"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e83d719e77deaca1470f6baf62a4d7743", // 95 chars
		"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e83d719e77deaca1470f6baf62a4d77430", // 97 chars
		string(make([]byte, 96)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		_ = ValidateSha384HexString(input)
	})
}

// FuzzValidateQueryParamKeys fuzzes handling of arbitrary URL query strings.
func FuzzValidateQueryParamKeys(f *testing.F) {
	f.Add("algorithm=AES", true)
	f.Add("", false)
	f.Add("x=1&x=2&x=3&x=4&x=5&x=6&x=7&x=8&x=9&x=10&x=11", false)
	f.Add("__proto__=polluted", false)

	f.Fuzz(func(t *testing.T, rawQuery string, hasAlgorithm bool) {
		params, err := url.ParseQuery(rawQuery)
		if err != nil {
			return // not a valid query string — skip
		}
		validKeys := map[string]bool{"algorithm": true, "key_length": true}
		if hasAlgorithm {
			validKeys["algorithm"] = true
		}
		_ = ValidateQueryParamKeys(params, validKeys)
	})
}
