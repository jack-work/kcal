// kcal — kelliher calendar CLI. Same architecture as gluck-todo-cli: RFC 8628
// device flow → hush-stored refresh token → Authorization: Bearer on
// every API call, with a single refresh-and-retry on 401.
//
// Subcommands: login / logout / whoami / ls / add / get / mv / rm /
// share. `mv` is a partial update — sets a subset of fields. Dates
// accept anything time.ParseInLocation understands via `dateparse`
// wrappers; the raw form '2026-07-30T09:00:00-04:00' always works too.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	hush "github.com/jack-work/hush/client"

	"github.com/jack-work/kcal/internal/api"
	"github.com/jack-work/kcal/internal/auth"
)

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	apiBase   = envDefault("KCAL_API", "https://cal.kelliher.info")
	issuer    = envDefault("KCAL_ISSUER", "https://auth.kelliher.info")
	clientID  = envDefault("KCAL_CLIENT_ID", "kcal")
	hushName  = envDefault("KCAL_HUSH_NAME", "kcal")
	envTokVar = "KCAL_TOKEN"
	scopes    = "openid profile groups offline_access"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	var err error
	switch cmd {
	case "login":
		err = cmdLogin()
	case "logout":
		err = cmdLogout()
	case "whoami":
		err = cmdWhoami()
	case "ls", "list":
		err = cmdList()
	case "add":
		err = cmdAdd()
	case "get":
		err = cmdGet()
	case "mv", "edit", "update":
		err = cmdUpdate()
	case "rm", "delete":
		err = cmdDelete()
	case "share":
		err = cmdShare()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: kcal <command> [args...]

commands:
  login                              authenticate via device flow
  logout                             forget the stored refresh token
  whoami                             print current user + groups (from the API)
  ls [--from DATE] [--to DATE]       list events (default: ±90d, RRULE-expanded)
  add "title" --at "WHEN" [flags]    create an event
  get <id>                           show one event (raw row, not expanded)
  mv <id> [flags]                    update fields on an event
  rm  <id>                           delete an event
  share <id> <user> <perms>          grant permissions (Read,Write,Delete,Share)

add / mv flags:
  --at "WHEN"           start time  (ISO 8601 or "2026-07-30 09:00")
  --end "WHEN"          end time
  --loc "PLACE"         location
  --desc "TEXT"         description
  --all-day             all-day event (start uses date only)
  --rrule "RRULE"       RFC 5545 RRULE text (RRULE:FREQ=WEEKLY;...)
  --title "TITLE"       (mv only) rename the event

env:
  KCAL_API         default: https://cal.kelliher.info
  KCAL_ISSUER      default: https://auth.kelliher.info
  KCAL_CLIENT_ID   default: kcal
  KCAL_TOKEN       escape hatch: raw bearer token (skips hush)
`)
}

func hushClient() (*hush.Client, error) {
	c, err := hush.New()
	if err != nil {
		return nil, fmt.Errorf("hush client: %w", err)
	}
	if err := c.Ping(); err != nil {
		return nil, fmt.Errorf("hush agent is not running (start it: hush up -d): %w", err)
	}
	return c, nil
}

func newResolver(h *hush.Client) *auth.Aggregate {
	return &auth.Aggregate{Strategies: []auth.CredentialStrategy{
		&auth.EnvVar{Name: envTokVar},
		&auth.OAuth{Hush: h, Name: hushName},
	}}
}

func newAPIClient() (*api.Client, error) {
	h, err := hushClient()
	if err != nil {
		return nil, err
	}
	return api.New(apiBase, newResolver(h)), nil
}

// ── commands ──────────────────────────────────────────────────────────

func cmdLogin() error {
	h, err := hushClient()
	if err != nil {
		return err
	}
	return auth.LoginDevice(h, auth.DeviceConfig{
		ProviderName:           hushName,
		DeviceAuthorizationURL: issuer + "/api/oidc/device-authorization",
		TokenURL:               issuer + "/api/oidc/token",
		AuthorizeURL:           issuer + "/api/oidc/authorization",
		ClientID:               clientID,
		Scopes:                 scopes,
	})
}

func cmdLogout() error {
	h, err := hushClient()
	if err != nil {
		return err
	}
	if err := h.OAuthDelete(hushName); err != nil {
		if errors.Is(err, hush.ErrOAuthNotFound) {
			fmt.Fprintln(os.Stderr, "already logged out")
			return nil
		}
		return fmt.Errorf("hush OAuthDelete: %w", err)
	}
	fmt.Fprintln(os.Stderr, "logged out (hush credential deleted)")
	return nil
}

func cmdWhoami() error {
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	w, err := c.Whoami()
	if err != nil {
		return err
	}
	fmt.Printf("user:   %s\n", w.User)
	fmt.Printf("groups: %s\n", strings.Join(w.Groups, ", "))
	return nil
}

func cmdList() error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	from := fs.String("from", "", "start of window (ISO 8601 or 'YYYY-MM-DD')")
	to := fs.String("to", "", "end of window (ISO 8601 or 'YYYY-MM-DD')")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	fromISO, err := parseWhen(*from)
	if err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	toISO, err := parseWhen(*to)
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	events, err := c.List(fromISO, toISO)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		fmt.Println("(no events in window)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tWHEN\tTITLE\tLOCATION")
	for _, e := range events {
		when := formatWhen(e.Dtstart, e.AllDay)
		if e.Recurring {
			when += " ↻"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", e.ID, when, e.Title, e.Location)
	}
	return tw.Flush()
}

func cmdAdd() error {
	title, flags, err := parseAddFlags(os.Args[1:])
	if err != nil {
		return err
	}
	if title == "" {
		return fmt.Errorf("usage: kcal add \"title\" --at \"WHEN\" [flags]")
	}
	if flags.at == "" {
		return fmt.Errorf("--at is required (start time)")
	}
	dtstart, err := parseWhen(flags.at)
	if err != nil {
		return fmt.Errorf("--at: %w", err)
	}
	var dtend string
	if flags.end != "" {
		dtend, err = parseWhen(flags.end)
		if err != nil {
			return fmt.Errorf("--end: %w", err)
		}
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	e, err := c.Create(api.CreateReq{
		Title:       title,
		Dtstart:     dtstart,
		Dtend:       dtend,
		AllDay:      flags.allDay,
		Location:    flags.loc,
		Description: flags.desc,
		RRULE:       flags.rrule,
	})
	if err != nil {
		return err
	}
	return prettyPrint(e)
}

func cmdGet() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: kcal get <id>")
	}
	id, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		return fmt.Errorf("id must be integer: %w", err)
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	e, err := c.Get(id)
	if err != nil {
		return err
	}
	return prettyPrint(e)
}

func cmdUpdate() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: kcal mv <id> [flags]")
	}
	id, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		return fmt.Errorf("id must be integer: %w", err)
	}
	_, flags, err := parseAddFlags(os.Args[2:]) // reuse the same parser; title from --title
	if err != nil {
		return err
	}
	req := api.UpdateReq{}
	if flags.title != "" {
		req.Title = &flags.title
	}
	if flags.at != "" {
		iso, err := parseWhen(flags.at)
		if err != nil {
			return fmt.Errorf("--at: %w", err)
		}
		req.Dtstart = &iso
	}
	if flags.end != "" {
		iso, err := parseWhen(flags.end)
		if err != nil {
			return fmt.Errorf("--end: %w", err)
		}
		req.Dtend = &iso
	}
	if flags.loc != "" {
		req.Location = &flags.loc
	}
	if flags.desc != "" {
		req.Description = &flags.desc
	}
	if flags.rrule != "" {
		req.RRULE = &flags.rrule
	}
	if flags.allDaySet {
		req.AllDay = &flags.allDay
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	e, err := c.Update(id, req)
	if err != nil {
		return err
	}
	return prettyPrint(e)
}

func cmdDelete() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: kcal rm <id>")
	}
	id, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		return fmt.Errorf("id must be integer: %w", err)
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	if err := c.Delete(id); err != nil {
		return err
	}
	fmt.Printf("deleted %d\n", id)
	return nil
}

func cmdShare() error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: kcal share <id> <user> <perm>[,<perm>...]")
	}
	id, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		return fmt.Errorf("id must be integer: %w", err)
	}
	user := os.Args[2]
	perms := strings.Split(os.Args[3], ",")
	for i := range perms {
		perms[i] = strings.TrimSpace(perms[i])
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	if err := c.Share(id, user, perms); err != nil {
		return err
	}
	fmt.Printf("shared %d with %s: %s\n", id, user, strings.Join(perms, ","))
	return nil
}

// ── flag parsing ──────────────────────────────────────────────────────

type addFlags struct {
	title     string
	at        string
	end       string
	loc       string
	desc      string
	rrule     string
	allDay    bool
	allDaySet bool
}

// parseAddFlags walks argv pulling recognized flags with `--x VAL` or
// `--x=VAL` shape. Anything left over joins into the positional title.
// Standalone --all-day is a boolean toggle. Unknown flags are errors.
func parseAddFlags(args []string) (string, addFlags, error) {
	var f addFlags
	var positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			positional = append(positional, a)
			i++
			continue
		}
		if a == "--all-day" {
			f.allDay, f.allDaySet = true, true
			i++
			continue
		}
		key, val, hasEq := strings.Cut(a, "=")
		if !hasEq {
			if i+1 >= len(args) {
				return "", f, fmt.Errorf("%s requires a value", a)
			}
			val = args[i+1]
			i += 2
		} else {
			i++
		}
		switch key {
		case "--title":
			f.title = val
		case "--at":
			f.at = val
		case "--end":
			f.end = val
		case "--loc", "--location":
			f.loc = val
		case "--desc", "--description":
			f.desc = val
		case "--rrule":
			f.rrule = val
		default:
			return "", f, fmt.Errorf("unknown flag: %s", key)
		}
	}
	return strings.Join(positional, " "), f, nil
}

// ── date/time parsing ─────────────────────────────────────────────────

// parseWhen accepts empty (returns ""), a bare date, or an ISO 8601
// datetime with optional offset. Bare "YYYY-MM-DD HH:MM" is interpreted
// in the local zone — that's what a human at a terminal expects.
func parseWhen(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	// Try a handful of layouts in order of specificity.
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			// Bare-date input keeps 00:00 local — good enough; the API
			// treats naive datetimes as UTC, but time.ParseInLocation
			// already stamps the local zone, so this round-trips cleanly.
			return t.Format(time.RFC3339), nil
		}
	}
	return "", fmt.Errorf("unrecognized date/time: %q (try RFC 3339 or 'YYYY-MM-DD HH:MM')", s)
}

// formatWhen renders an ISO string for the ls table. All-day events
// show just the date; timed events show local-clock HH:MM plus date.
func formatWhen(iso string, allDay bool) string {
	if iso == "" {
		return "—"
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return iso
	}
	local := t.Local()
	if allDay {
		return local.Format("2006-01-02")
	}
	return local.Format("2006-01-02 15:04")
}

func prettyPrint(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
