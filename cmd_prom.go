package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"dnsops/internal/dnssec"
	"dnsops/internal/expiry"
	"dnsops/internal/mailcheck"
	"dnsops/internal/verify"
)

func resolveStructuredOutput(jsonOut, yamlOut, promOut bool) (outputFormat, error) {
	if promOut {
		if jsonOut || yamlOut {
			return "", fmt.Errorf("--prom is mutually exclusive with --json and --yaml")
		}
		return outputProm, nil
	}
	return resolveOutputFormat(jsonOut, yamlOut)
}

func printVerifyProm(report verify.Report) {
	fmt.Println("# HELP dnsops_verify_check_ok DNS verify check status (1=ok, 0=failed).")
	fmt.Println("# TYPE dnsops_verify_check_ok gauge")
	for _, result := range report.Results {
		fmt.Printf(
			"dnsops_verify_check_ok{%s} %d\n",
			promLabels(map[string]string{
				"file":     report.File,
				"resolver": report.Resolver,
				"name":     result.Name,
				"type":     result.Type,
			}),
			boolToFloat(result.OK),
		)
	}
	fmt.Println("# HELP dnsops_verify_summary_matched Number of matched checks.")
	fmt.Println("# TYPE dnsops_verify_summary_matched gauge")
	fmt.Printf("dnsops_verify_summary_matched{%s} %d\n", promLabels(map[string]string{
		"file":     report.File,
		"resolver": report.Resolver,
	}), report.Matched)
	fmt.Println("# HELP dnsops_verify_summary_total Total number of checks.")
	fmt.Println("# TYPE dnsops_verify_summary_total gauge")
	fmt.Printf("dnsops_verify_summary_total{%s} %d\n", promLabels(map[string]string{
		"file":     report.File,
		"resolver": report.Resolver,
	}), report.Total)
	fmt.Println("# HELP dnsops_verify_summary_errors Number of failed checks.")
	fmt.Println("# TYPE dnsops_verify_summary_errors gauge")
	fmt.Printf("dnsops_verify_summary_errors{%s} %d\n", promLabels(map[string]string{
		"file":     report.File,
		"resolver": report.Resolver,
	}), report.Errors)
}

func printExpiryProm(reports []expiry.Report) {
	fmt.Println("# HELP dnsops_expiry_days_remaining Days remaining until domain expiration.")
	fmt.Println("# TYPE dnsops_expiry_days_remaining gauge")
	fmt.Println("# HELP dnsops_expiry_status Domain expiry status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE dnsops_expiry_status gauge")
	fmt.Println("# HELP dnsops_expiry_error RDAP lookup error status (1=error, 0=success).")
	fmt.Println("# TYPE dnsops_expiry_error gauge")
	for _, rep := range reports {
		labels := map[string]string{"domain": rep.Domain}
		if rep.ExpiresAt != "" {
			fmt.Printf("dnsops_expiry_days_remaining{%s} %d\n", promLabels(labels), rep.DaysRemaining)
		}
		for _, severity := range []string{"ok", "warn", "critical", "error"} {
			value := 0
			if rep.Severity == severity {
				value = 1
			}
			fmt.Printf("dnsops_expiry_status{%s} %d\n", promLabels(map[string]string{
				"domain":   rep.Domain,
				"severity": severity,
			}), value)
		}
		fmt.Printf("dnsops_expiry_error{%s} %d\n", promLabels(labels), boolToFloat(rep.Error != ""))
	}
}

func printDNSSECProm(reports []dnssec.Report) {
	fmt.Println("# HELP dnsops_dnssec_status DNSSEC status by domain (1=current status, 0=otherwise).")
	fmt.Println("# TYPE dnsops_dnssec_status gauge")
	fmt.Println("# HELP dnsops_dnssec_child_dnskey_count Number of child DNSKEY records.")
	fmt.Println("# TYPE dnsops_dnssec_child_dnskey_count gauge")
	fmt.Println("# HELP dnsops_dnssec_child_rrsig_count Number of child DNSKEY-covering RRSIG records.")
	fmt.Println("# TYPE dnsops_dnssec_child_rrsig_count gauge")
	fmt.Println("# HELP dnsops_dnssec_parent_ds_count Number of parent DS records.")
	fmt.Println("# TYPE dnsops_dnssec_parent_ds_count gauge")
	for _, report := range reports {
		for _, status := range []string{"signed", "unsigned", "broken", "error"} {
			value := 0
			if report.Status == status {
				value = 1
			}
			fmt.Printf("dnsops_dnssec_status{%s} %d\n", promLabels(map[string]string{
				"domain": report.Domain,
				"status": status,
			}), value)
		}
		labels := map[string]string{
			"domain":   report.Domain,
			"resolver": report.Resolver,
		}
		fmt.Printf("dnsops_dnssec_child_dnskey_count{%s} %d\n", promLabels(labels), report.ChildDNSKEYCount)
		fmt.Printf("dnsops_dnssec_child_rrsig_count{%s} %d\n", promLabels(labels), report.ChildRRSIGCount)
		fmt.Printf("dnsops_dnssec_parent_ds_count{%s} %d\n", promLabels(labels), report.ParentDSCount)
	}
}

func printMailProm(reports []mailcheck.Report) {
	fmt.Println("# HELP dnsops_mail_errors Number of hard mail-DNS errors for a domain.")
	fmt.Println("# TYPE dnsops_mail_errors gauge")
	fmt.Println("# HELP dnsops_mail_warnings Number of mail-DNS warnings for a domain.")
	fmt.Println("# TYPE dnsops_mail_warnings gauge")
	fmt.Println("# HELP dnsops_mail_status Mail-DNS aggregate status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE dnsops_mail_status gauge")
	fmt.Println("# HELP dnsops_mail_record_present Presence of key mail DNS records (1=present, 0=missing).")
	fmt.Println("# TYPE dnsops_mail_record_present gauge")
	fmt.Println("# HELP dnsops_mail_dkim_selector_ok DKIM selector presence/health (1=ok, 0=missing or error).")
	fmt.Println("# TYPE dnsops_mail_dkim_selector_ok gauge")
	for _, report := range reports {
		base := map[string]string{
			"domain":   report.Domain,
			"resolver": report.Resolver,
		}
		fmt.Printf("dnsops_mail_errors{%s} %d\n", promLabels(base), report.Errors)
		fmt.Printf("dnsops_mail_warnings{%s} %d\n", promLabels(base), report.Warnings)

		status := "ok"
		if report.Errors > 0 {
			status = "error"
		} else if report.Warnings > 0 {
			status = "warn"
		}
		for _, level := range []string{"ok", "warn", "error"} {
			value := 0
			if status == level {
				value = 1
			}
			fmt.Printf("dnsops_mail_status{%s} %d\n", promLabels(map[string]string{
				"domain":   report.Domain,
				"resolver": report.Resolver,
				"status":   level,
			}), value)
		}

		fmt.Printf("dnsops_mail_record_present{%s} %d\n", promLabels(map[string]string{
			"domain":   report.Domain,
			"resolver": report.Resolver,
			"record":   "mx",
		}), boolToFloat(len(report.MX) > 0))
		fmt.Printf("dnsops_mail_record_present{%s} %d\n", promLabels(map[string]string{
			"domain":   report.Domain,
			"resolver": report.Resolver,
			"record":   "spf",
		}), boolToFloat(len(report.SPF) > 0))
		fmt.Printf("dnsops_mail_record_present{%s} %d\n", promLabels(map[string]string{
			"domain":   report.Domain,
			"resolver": report.Resolver,
			"record":   "dmarc",
		}), boolToFloat(len(report.DMARC) > 0))

		for _, row := range report.DKIM {
			fmt.Printf("dnsops_mail_dkim_selector_ok{%s} %d\n", promLabels(map[string]string{
				"domain":   report.Domain,
				"resolver": report.Resolver,
				"selector": row.Selector,
			}), boolToFloat(row.Error == "" && len(row.Values) > 0))
		}
	}
}

func promLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key, value := range labels {
		if strings.TrimSpace(value) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Quote(labels[key]))
	}
	return strings.Join(parts, ",")
}

func boolToFloat(ok bool) int {
	if ok {
		return 1
	}
	return 0
}
