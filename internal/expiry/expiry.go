package expiry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Event struct {
	Action string    `json:"action"`
	Date   time.Time `json:"date"`
}

type Report struct {
	Domain        string   `json:"domain"`
	RDAPURL       string   `json:"rdap_url"`
	Registrar     string   `json:"registrar,omitempty"`
	Nameservers   []string `json:"nameservers,omitempty"`
	Statuses      []string `json:"statuses,omitempty"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
	DaysRemaining int      `json:"days_remaining,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type rdapResponse struct {
	Events      []rdapEvent  `json:"events"`
	Status      []string     `json:"status"`
	Nameservers []rdapNS     `json:"nameservers"`
	Entities    []rdapEntity `json:"entities"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapEntity struct {
	Roles       []string        `json:"roles"`
	VCardArray  []any           `json:"vcardArray"`
	PublicIDs   []rdapPublicID  `json:"publicIds"`
	Handle      string          `json:"handle"`
	Entities    []rdapEntity    `json:"entities"`
}

type rdapPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

func Lookup(ctx context.Context, client *http.Client, domain string, warnDays, criticalDays int) (Report, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return Report{}, fmt.Errorf("domain is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	url := "https://rdap.org/domain/" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Report{}, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Report{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return Report{}, fmt.Errorf("rdap lookup failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var raw rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Report{}, err
	}
	rep := Report{
		Domain:      domain,
		RDAPURL:     url,
		Registrar:   registrarName(raw.Entities),
		Nameservers: nameserverNames(raw.Nameservers),
		Statuses:    append([]string(nil), raw.Status...),
	}
	expiresAt, ok := expirationDate(raw.Events)
	if !ok {
		return rep, fmt.Errorf("no expiration event in RDAP response")
	}
	rep.ExpiresAt = expiresAt.Format(time.RFC3339)
	rep.DaysRemaining = daysRemaining(expiresAt, time.Now().UTC())
	rep.Severity = classify(rep.DaysRemaining, warnDays, criticalDays)
	return rep, nil
}

func expirationDate(events []rdapEvent) (time.Time, bool) {
	for _, ev := range events {
		action := strings.ToLower(strings.TrimSpace(ev.Action))
		if action != "expiration" && action != "expiry" && action != "expired" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339, ev.Date); err == nil {
			return ts.UTC(), true
		}
	}
	return time.Time{}, false
}

func nameserverNames(in []rdapNS) []string {
	out := make([]string, 0, len(in))
	for _, ns := range in {
		if ns.LDHName != "" {
			out = append(out, ns.LDHName)
		}
	}
	return out
}

func registrarName(entities []rdapEntity) string {
	for _, e := range entities {
		if hasRole(e.Roles, "registrar") {
			if name := vcardFN(e.VCardArray); name != "" {
				return name
			}
			if e.Handle != "" {
				return e.Handle
			}
		}
		if name := registrarName(e.Entities); name != "" {
			return name
		}
	}
	return ""
}

func hasRole(roles []string, want string) bool {
	for _, role := range roles {
		if strings.EqualFold(strings.TrimSpace(role), want) {
			return true
		}
	}
	return false
}

func vcardFN(vcard []any) string {
	if len(vcard) != 2 {
		return ""
	}
	rows, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, row := range rows {
		cols, ok := row.([]any)
		if !ok || len(cols) < 4 {
			continue
		}
		key, _ := cols[0].(string)
		if strings.EqualFold(key, "fn") {
			if val, ok := cols[3].(string); ok {
				return val
			}
		}
	}
	return ""
}

func daysRemaining(expiresAt, now time.Time) int {
	return int(expiresAt.Sub(now).Hours() / 24)
}

func classify(days, warnDays, criticalDays int) string {
	switch {
	case days <= criticalDays:
		return "critical"
	case days <= warnDays:
		return "warn"
	default:
		return "ok"
	}
}
