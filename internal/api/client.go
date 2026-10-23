// Package api is a thin HTTP client for gluck-calendar. Same shape as
// gluck-todo-cli: every call goes through a resolver that supplies the
// current bearer token; on a 401 the client asks the resolver to
// invalidate the token (which triggers a hush refresh) and retries once.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Resolver interface {
	Resolve() (string, error)
	Invalidate(token string) error
}

type Client struct {
	Base     string
	Resolver Resolver
	HTTP     *http.Client
}

func New(base string, resolver Resolver) *Client {
	return &Client{
		Base:     strings.TrimRight(base, "/"),
		Resolver: resolver,
		HTTP:     http.DefaultClient,
	}
}

func (c *Client) do(method, path string, body any, out any) error {
	var attempt func(retry bool) error
	attempt = func(retry bool) error {
		tok, err := c.Resolver.Resolve()
		if err != nil {
			return err
		}
		var reqBody io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("marshal request: %w", err)
			}
			reqBody = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, c.Base+path, reqBody)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && !retry {
			if err := c.Resolver.Invalidate(tok); err != nil {
				return fmt.Errorf("token rejected and refresh failed: %w", err)
			}
			return attempt(true)
		}
		bs, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(bs)))
		}
		if out != nil && len(bs) > 0 {
			if err := json.Unmarshal(bs, out); err != nil {
				return fmt.Errorf("decode response: %w (body: %s)", err, string(bs))
			}
		}
		return nil
	}
	return attempt(false)
}

// Event mirrors the server's JSON. Instance rows from GET /events also
// deserialize into this — extra fields (`recurring`) are ignored by
// json.Unmarshal, and Instance keeps a superset field.
type Event struct {
	ID          int64  `json:"id"`
	UID         string `json:"uid"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Dtstart     string `json:"dtstart"`
	Dtend       string `json:"dtend"`
	AllDay      bool   `json:"all_day"`
	RRULE       string `json:"rrule"`
	Source      string `json:"source"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// Instance is what GET /events returns: expanded occurrences (may not have id-uniqueness within a list when RRULE-expanded).
type Instance struct {
	Event
	Recurring bool `json:"recurring"`
}

func (c *Client) List(from, to string) ([]Instance, error) {
	q := url.Values{}
	if from != "" {
		q.Set("from", from)
	}
	if to != "" {
		q.Set("to", to)
	}
	path := "/events"
	if s := q.Encode(); s != "" {
		path += "?" + s
	}
	var out []Instance
	err := c.do(http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) Get(id int64) (*Event, error) {
	var e Event
	err := c.do(http.MethodGet, fmt.Sprintf("/events/%d", id), nil, &e)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// CreateReq is the POST body. Zero-valued fields are omitted so callers
// don't accidentally clear location/description/etc.
type CreateReq struct {
	Title       string `json:"title"`
	Dtstart     string `json:"dtstart"`
	Dtend       string `json:"dtend,omitempty"`
	AllDay      bool   `json:"all_day,omitempty"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`
	RRULE       string `json:"rrule,omitempty"`
	UID         string `json:"uid,omitempty"`
	Source      string `json:"source,omitempty"`
}

func (c *Client) Create(req CreateReq) (*Event, error) {
	var e Event
	err := c.do(http.MethodPost, "/events", req, &e)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// UpdateReq is the PUT body. Pointer fields let the server tell "not set"
// from "explicitly empty" — the API keeps the current value when a key
// is absent from the JSON.
type UpdateReq struct {
	Title       *string `json:"title,omitempty"`
	Dtstart     *string `json:"dtstart,omitempty"`
	Dtend       *string `json:"dtend,omitempty"`
	AllDay      *bool   `json:"all_day,omitempty"`
	Location    *string `json:"location,omitempty"`
	Description *string `json:"description,omitempty"`
	RRULE       *string `json:"rrule,omitempty"`
	Source      *string `json:"source,omitempty"`
}

func (c *Client) Update(id int64, req UpdateReq) (*Event, error) {
	var e Event
	err := c.do(http.MethodPut, fmt.Sprintf("/events/%d", id), req, &e)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (c *Client) Delete(id int64) error {
	return c.do(http.MethodDelete, fmt.Sprintf("/events/%d", id), nil, nil)
}

func (c *Client) Share(id int64, username string, perms []string) error {
	req := map[string]any{"username": username, "permissions": perms}
	return c.do(http.MethodPost, fmt.Sprintf("/events/%d/share", id), req, nil)
}

// Whoami is unauthenticated-friendly on our server (it just echoes back
// the resolved Remote-User); useful for confirming the bearer token is
// wired up correctly.
type CalendarShare struct {
	Owner       string   `json:"owner"`
	Grantee     string   `json:"grantee"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at,omitempty"`
}

type SharesResp struct {
	Granted  []CalendarShare `json:"granted"`
	Received []CalendarShare `json:"received"`
}

func (c *Client) Grants() (*SharesResp, error) {
	var s SharesResp
	if err := c.do(http.MethodGet, "/shares", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) Grant(grantee string) (*CalendarShare, error) {
	var s CalendarShare
	req := map[string]any{"grantee": grantee, "permissions": []string{"Read"}}
	if err := c.do(http.MethodPost, "/shares", req, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) Revoke(grantee string) error {
	return c.do(http.MethodDelete, "/shares/"+url.PathEscape(grantee), nil, nil)
}

type WhoamiResp struct {
	User   string   `json:"user"`
	Groups []string `json:"groups"`
}

func (c *Client) Whoami() (*WhoamiResp, error) {
	var w WhoamiResp
	err := c.do(http.MethodGet, "/whoami", nil, &w)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func (c *Client) Health() error {
	req, err := http.NewRequest(http.MethodGet, c.Base+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bs, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health: %d %s", resp.StatusCode, strings.TrimSpace(string(bs)))
	}
	return nil
}
