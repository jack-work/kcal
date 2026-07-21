// Package auth's device flow: RFC 8628 device authorization grant, the
// only OAuth flow that behaves sensibly when the CLI has no browser (SSH
// sessions, servers, IoT). The steps are:
//
//  1. POST client_id + scope to Authelia's device-authorization endpoint.
//     Get back device_code, user_code, verification_uri[_complete],
//     expires_in, interval.
//  2. Print the user_code + verification URL to stderr; user opens the
//     URL on any device with a browser and confirms.
//  3. Meanwhile, poll the token endpoint every `interval` seconds with
//     grant_type=urn:ietf:params:oauth:grant-type:device_code + device_code.
//     Authelia returns 400 authorization_pending / slow_down until the
//     user approves; then 200 with access_token + refresh_token.
//  4. Hand the tokens to hush's OAuthRegister; hush owns rotation from
//     that point onward.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	hush "github.com/jack-work/hush/client"
)

// DeviceConfig is what a device-flow login needs to know about the provider.
type DeviceConfig struct {
	ProviderName            string // hush credential name
	DeviceAuthorizationURL  string // https://.../api/oidc/device-authorization
	TokenURL                string // https://.../api/oidc/token
	AuthorizeURL            string // https://.../api/oidc/authorization (unused; kept for OAuthRegister)
	ClientID                string
	Scopes                  string // space-separated
}

type deviceAuthResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// LoginDevice runs the RFC 8628 flow end-to-end and registers the result
// with the hush agent. Blocks until the user approves, denies, or the
// device_code expires.
func LoginDevice(hushClient *hush.Client, cfg DeviceConfig) error {
	if err := hushClient.Ping(); err != nil {
		return fmt.Errorf("hush agent is not running. Start it: hush up -d")
	}

	// Step 1: ask for a device code.
	form := url.Values{
		"client_id": {cfg.ClientID},
		"scope":     {cfg.Scopes},
	}
	req, err := http.NewRequest(http.MethodPost, cfg.DeviceAuthorizationURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build device-authorization request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("device-authorization request: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("device-authorization failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var da deviceAuthResp
	if err := json.Unmarshal(body, &da); err != nil {
		return fmt.Errorf("parse device-authorization response: %w (body: %s)", err, string(body))
	}
	if da.DeviceCode == "" || da.UserCode == "" {
		return fmt.Errorf("device-authorization response missing required fields: %s", string(body))
	}
	if da.Interval <= 0 {
		da.Interval = 5
	}
	if da.ExpiresIn <= 0 {
		da.ExpiresIn = 600
	}

	verify := da.VerificationURIComplete
	if verify == "" {
		verify = da.VerificationURI
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Open this URL on any device with a browser:")
	fmt.Fprintln(os.Stderr, "    "+verify)
	if da.VerificationURIComplete != "" && da.VerificationURI != da.VerificationURIComplete {
		fmt.Fprintln(os.Stderr, "  (or "+da.VerificationURI+" and enter code "+da.UserCode+")")
	} else {
		fmt.Fprintln(os.Stderr, "  User code: "+da.UserCode)
	}
	fmt.Fprintln(os.Stderr, "  Waiting for approval...")

	// Step 2/3: poll the token endpoint until we get a token or a hard error.
	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	interval := time.Duration(da.Interval) * time.Second

	for time.Now().Before(deadline) {
		time.Sleep(interval)
		tok, err := pollDeviceToken(cfg.TokenURL, cfg.ClientID, da.DeviceCode)
		if err == nil {
			// Success. Hand the credential to hush and we're done.
			if err := hushClient.OAuthRegister(hush.OAuthRegisterRequest{
				Name:         cfg.ProviderName,
				AuthorizeURL: cfg.AuthorizeURL,
				TokenURL:     cfg.TokenURL,
				RedirectURI:  "http://localhost/callback",
				ClientID:     cfg.ClientID,
				Scopes:       cfg.Scopes,
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				ExpiresIn:    tok.ExpiresIn,
			}); err != nil {
				return fmt.Errorf("register with hush: %w", err)
			}
			fmt.Fprintf(os.Stderr, "  Logged in (token expires in %ds)\n", tok.ExpiresIn)
			return nil
		}
		var pending *pendingError
		var slow *slowDownError
		switch {
		case errors.As(err, &pending):
			// keep polling
		case errors.As(err, &slow):
			interval += 5 * time.Second
		default:
			return err
		}
	}
	return fmt.Errorf("device code expired before approval; run login again")
}

type pendingError struct{ Description string }

func (e *pendingError) Error() string { return "authorization pending: " + e.Description }

type slowDownError struct{ Description string }

func (e *slowDownError) Error() string { return "slow down: " + e.Description }

func pollDeviceToken(tokenURL, clientID, deviceCode string) (*tokenResp, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token poll: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var tr tokenResp
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token response (%d): %s", resp.StatusCode, string(body))
	}
	if resp.StatusCode == http.StatusOK && tr.AccessToken != "" {
		return &tr, nil
	}
	switch tr.Error {
	case "authorization_pending":
		return nil, &pendingError{Description: tr.ErrorDesc}
	case "slow_down":
		return nil, &slowDownError{Description: tr.ErrorDesc}
	case "access_denied":
		return nil, fmt.Errorf("access denied by user")
	case "expired_token":
		return nil, fmt.Errorf("device code expired")
	default:
		return nil, fmt.Errorf("token endpoint returned %d: %s %s", resp.StatusCode, tr.Error, tr.ErrorDesc)
	}
}
