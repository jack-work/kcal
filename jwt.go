package main

import (
	"encoding/base64"
	"encoding/json"
)

// decodeJWTClaims parses the middle segment of a JWT into a claims map.
// URL-safe base64 without padding — jwt payloads are always encoded that way.
func decodeJWTClaims(payload string) (map[string]any, error) {
	bs, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(bs, &m); err != nil {
		return nil, err
	}
	return m, nil
}
