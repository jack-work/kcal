// Package auth mirrors figaro's credential-strategy shape: an Aggregate
// walks a priority list of strategies, returning the first that succeeds.
// On a 401 the caller invalidates the token and calls Resolve again;
// OAuth-backed strategies force a hush refresh, then the next call sees
// a fresh access token. Env-var and static strategies are here for
// escape hatches (e.g. dropping a pre-minted token into GLUCK_TODO_TOKEN).
package auth

import (
	"errors"
	"fmt"
	"os"

	hush "github.com/jack-work/hush/client"
)

// CredentialStrategy is one source of API credentials.
type CredentialStrategy interface {
	TryResolve() (token string, ok bool, err error)
	// Invalidate is called when a token is rejected (e.g. 401). A
	// non-nil error means invalidation itself failed (e.g. an OAuth
	// refresh was rejected outright).
	Invalidate(token string) error
}

// Aggregate walks strategies in priority order. Re-evaluates on each
// call so config/env changes are picked up without restart.
type Aggregate struct {
	Strategies []CredentialStrategy
}

func (a *Aggregate) Resolve() (string, error) {
	var firstErr error
	for _, s := range a.Strategies {
		tok, ok, err := s.TryResolve()
		if ok {
			return tok, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return "", fmt.Errorf("no credential available; first strategy error: %w", firstErr)
	}
	return "", errors.New("no credential available (run: todo login)")
}

func (a *Aggregate) Invalidate(token string) error {
	var errs []error
	for _, s := range a.Strategies {
		if err := s.Invalidate(token); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// EnvVar reads a token from an env var. Escape hatch for CI / bootstrap.
type EnvVar struct{ Name string }

func (e *EnvVar) TryResolve() (string, bool, error) {
	if e.Name == "" {
		return "", false, nil
	}
	v := os.Getenv(e.Name)
	if v == "" {
		return "", false, nil
	}
	return v, true, nil
}

func (*EnvVar) Invalidate(string) error { return nil }

// OAuth reads the current access token for a named credential from the
// hush agent and forces a refresh on Invalidate. Hush owns the refresh
// token and rotation loop; we only ask for a live access token and let
// hush surface hard failures via ErrOAuthRefreshPermanent.
type OAuth struct {
	Hush *hush.Client
	Name string
}

func (o *OAuth) TryResolve() (string, bool, error) {
	if o.Hush == nil || o.Name == "" {
		return "", false, nil
	}
	tok, err := o.Hush.OAuthGet(o.Name)
	if err != nil {
		if errors.Is(err, hush.ErrOAuthNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	return tok, true, nil
}

func (o *OAuth) Invalidate(token string) error {
	if o.Hush == nil || o.Name == "" {
		return nil
	}
	_, err := o.Hush.OAuthRefresh(o.Name)
	if err == nil {
		return nil
	}
	if errors.Is(err, hush.ErrOAuthRefreshPermanent) {
		return fmt.Errorf("oauth refresh for %q rejected (run: todo login): %w", o.Name, err)
	}
	return fmt.Errorf("oauth refresh for %q: %w", o.Name, err)
}
