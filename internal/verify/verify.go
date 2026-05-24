package verify

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"dnsops/internal/dnsquery"
	"dnsops/internal/rawdns"

	"gopkg.in/yaml.v3"
)

type Spec struct {
	Zone   string  `yaml:"zone" json:"zone"`
	Checks []Check `yaml:"checks" json:"checks"`
}

type Check struct {
	Name         string   `yaml:"name" json:"name"`
	Type         string   `yaml:"type" json:"type"`
	Values       []string `yaml:"values" json:"values"`
	Contains     []string `yaml:"contains" json:"contains"`
	Regex        string   `yaml:"regex" json:"regex"`
	MustExist    bool     `yaml:"must_exist" json:"must_exist"`
	MustNotExist bool     `yaml:"must_not_exist" json:"must_not_exist"`
	MinTTL       uint32   `yaml:"min_ttl" json:"min_ttl"`
	MaxTTL       uint32   `yaml:"max_ttl" json:"max_ttl"`
}

type CheckResult struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Actual       []string `json:"actual,omitempty"`
	Expected     []string `json:"expected,omitempty"`
	Contains     []string `json:"contains,omitempty"`
	Regex        string   `json:"regex,omitempty"`
	MustExist    bool     `json:"must_exist,omitempty"`
	MustNotExist bool     `json:"must_not_exist,omitempty"`
	MinTTL       uint32   `json:"min_ttl,omitempty"`
	MaxTTL       uint32   `json:"max_ttl,omitempty"`
	ActualTTLs   []uint32 `json:"actual_ttls,omitempty"`
	OK           bool     `json:"ok"`
	Error        string   `json:"error,omitempty"`
}

type Report struct {
	File     string        `json:"file"`
	Resolver string        `json:"resolver"`
	Zone     string        `json:"zone,omitempty"`
	Results  []CheckResult `json:"results"`
	Matched  int           `json:"matched"`
	Total    int           `json:"total"`
	Errors   int           `json:"errors"`
}

func Load(path string) (Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, err
	}
	var spec Spec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return Spec{}, err
	}
	if len(spec.Checks) == 0 {
		return Spec{}, fmt.Errorf("spec has no checks")
	}
	for i, c := range spec.Checks {
		if err := validateCheck(c); err != nil {
			return Spec{}, fmt.Errorf("checks[%d]: %w", i, err)
		}
	}
	return spec, nil
}

func Run(ctx context.Context, resolver, file string, spec Spec) Report {
	report := Report{
		File:     file,
		Resolver: dnsquery.NormalizeResolver(resolver),
		Zone:     spec.Zone,
		Results:  make([]CheckResult, 0, len(spec.Checks)),
		Total:    len(spec.Checks),
	}
	for _, chk := range spec.Checks {
		row := CheckResult{
			Name:         chk.Name,
			Type:         strings.ToUpper(chk.Type),
			Expected:     cloneAndSort(chk.Values),
			Contains:     append([]string(nil), chk.Contains...),
			Regex:        chk.Regex,
			MustExist:    chk.MustExist,
			MustNotExist: chk.MustNotExist,
			MinTTL:       chk.MinTTL,
			MaxTTL:       chk.MaxTTL,
		}
		res, err := rawdns.Query(ctx, resolver, chk.Name, chk.Type)
		if err != nil {
			if chk.MustNotExist && isNotFoundErr(err) {
				row.OK = true
				report.Matched++
				report.Results = append(report.Results, row)
				continue
			}
			row.Error = err.Error()
			report.Errors++
			report.Results = append(report.Results, row)
			continue
		}
		row.Actual = recordValues(res)
		row.ActualTTLs = recordTTLs(res)
		if matchCheck(chk, res) {
			row.OK = true
			report.Matched++
		} else {
			row.Error = mismatchMessage(chk, res)
			report.Errors++
		}
		report.Results = append(report.Results, row)
	}
	return report
}

func validateCheck(c Check) error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(c.Type) == "" {
		return fmt.Errorf("type is required")
	}
	matchers := 0
	if len(c.Values) > 0 {
		matchers++
	}
	if len(c.Contains) > 0 {
		matchers++
	}
	if strings.TrimSpace(c.Regex) != "" {
		matchers++
		if _, err := regexp.Compile(c.Regex); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
	}
	if c.MustExist {
		matchers++
	}
	if c.MustNotExist {
		matchers++
	}
	if c.MustExist && c.MustNotExist {
		return fmt.Errorf("must_exist and must_not_exist are mutually exclusive")
	}
	if matchers == 0 {
		return fmt.Errorf("one of values, contains, regex, must_exist or must_not_exist is required")
	}
	if len(c.Values) > 0 && (len(c.Contains) > 0 || strings.TrimSpace(c.Regex) != "" || c.MustExist || c.MustNotExist) {
		return fmt.Errorf("values is mutually exclusive with other matchers")
	}
	if len(c.Contains) > 0 && (strings.TrimSpace(c.Regex) != "" || c.MustExist || c.MustNotExist) {
		return fmt.Errorf("contains is mutually exclusive with other matchers")
	}
	if strings.TrimSpace(c.Regex) != "" && (c.MustExist || c.MustNotExist) {
		return fmt.Errorf("regex is mutually exclusive with existence matchers")
	}
	if c.MinTTL > 0 && c.MaxTTL > 0 && c.MinTTL > c.MaxTTL {
		return fmt.Errorf("min_ttl cannot be greater than max_ttl")
	}
	return nil
}

func matchCheck(c Check, actual []rawdns.Record) bool {
	values := recordValues(actual)
	if c.MustExist {
		return len(actual) > 0 && ttlOK(c, actual)
	}
	if c.MustNotExist {
		return len(actual) == 0
	}
	if len(c.Values) > 0 {
		return slices.Equal(cloneAndSort(c.Values), cloneAndSort(values)) && ttlOK(c, actual)
	}
	if len(c.Contains) > 0 {
		for _, got := range values {
			ok := true
			for _, fragment := range c.Contains {
				if !strings.Contains(got, fragment) {
					ok = false
					break
				}
			}
			if ok {
				return ttlOK(c, actual)
			}
		}
		return false
	}
	if strings.TrimSpace(c.Regex) != "" {
		re := regexp.MustCompile(c.Regex)
		for _, got := range values {
			if re.MatchString(got) {
				return ttlOK(c, actual)
			}
		}
	}
	return false
}

func ttlOK(c Check, actual []rawdns.Record) bool {
	if len(actual) == 0 {
		return c.MinTTL == 0 && c.MaxTTL == 0
	}
	for _, rec := range actual {
		if c.MinTTL > 0 && rec.TTL < c.MinTTL {
			return false
		}
		if c.MaxTTL > 0 && rec.TTL > c.MaxTTL {
			return false
		}
	}
	return true
}

func mismatchMessage(c Check, actual []rawdns.Record) string {
	values := recordValues(actual)
	if c.MustExist {
		if len(actual) == 0 {
			return "expected record to exist, got no answers"
		}
		return ttlMismatchMessage(c, actual, "record exists but TTL constraints failed")
	}
	if c.MustNotExist {
		return fmt.Sprintf("expected record to not exist, got %v", values)
	}
	if len(c.Values) > 0 {
		if !slices.Equal(cloneAndSort(c.Values), cloneAndSort(values)) {
			return fmt.Sprintf("expected exact values %v, got %v", cloneAndSort(c.Values), cloneAndSort(values))
		}
		return ttlMismatchMessage(c, actual, "expected values matched but TTL constraints failed")
	}
	if len(c.Contains) > 0 {
		for _, got := range values {
			ok := true
			for _, fragment := range c.Contains {
				if !strings.Contains(got, fragment) {
					ok = false
					break
				}
			}
			if ok {
				return ttlMismatchMessage(c, actual, "contains matched but TTL constraints failed")
			}
		}
		return fmt.Sprintf("expected one record containing all fragments %v in %v", c.Contains, values)
	}
	if strings.TrimSpace(c.Regex) != "" {
		re := regexp.MustCompile(c.Regex)
		for _, got := range values {
			if re.MatchString(got) {
				return ttlMismatchMessage(c, actual, "regex matched but TTL constraints failed")
			}
		}
		return fmt.Sprintf("expected one record matching regex %q in %v", c.Regex, values)
	}
	return "check did not match"
}

func ttlMismatchMessage(c Check, actual []rawdns.Record, prefix string) string {
	ttls := recordTTLs(actual)
	switch {
	case c.MinTTL > 0 && c.MaxTTL > 0:
		return fmt.Sprintf("%s: expected TTLs in range [%d,%d], got %v", prefix, c.MinTTL, c.MaxTTL, ttls)
	case c.MinTTL > 0:
		return fmt.Sprintf("%s: expected TTLs >= %d, got %v", prefix, c.MinTTL, ttls)
	case c.MaxTTL > 0:
		return fmt.Sprintf("%s: expected TTLs <= %d, got %v", prefix, c.MaxTTL, ttls)
	default:
		return prefix
	}
}

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "NXDOMAIN") || strings.Contains(msg, "NO SOA ANSWER")
}

func cloneAndSort(in []string) []string {
	out := append([]string(nil), in...)
	slices.Sort(out)
	return out
}

func recordValues(in []rawdns.Record) []string {
	out := make([]string, 0, len(in))
	for _, rec := range in {
		out = append(out, rec.Data)
	}
	return out
}

func recordTTLs(in []rawdns.Record) []uint32 {
	out := make([]uint32, 0, len(in))
	for _, rec := range in {
		out = append(out, rec.TTL)
	}
	return out
}
