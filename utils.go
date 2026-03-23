package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	divByOneKAt   = 524288    // 512k
	divByOneMegAt = 536870912 // 512m
	oneK          = 1024
	oneMeg        = 1048576
)

// adjIntUnits returns (value, unit) for integer display.
// Matches Perl's adj_int_units exactly.
func adjIntUnits(value int) (int, string) {
	if value == 0 {
		return 0, " "
	}
	if value > divByOneMegAt {
		return value / oneMeg, "m"
	}
	if value > divByOneKAt {
		return value / oneK, "k"
	}
	return value, " "
}

// adjIntUnitsFloat returns (float value, unit) for integer display when averaging.
func adjIntUnitsFloat(value float64) (float64, string) {
	if value == 0 {
		return 0, " "
	}
	if value > divByOneMegAt {
		return value / oneMeg, "m"
	}
	if value > divByOneKAt {
		return value / oneK, "k"
	}
	return value, " "
}

// adjTimeUnits returns (value, unit) for time display.
// Matches Perl's adj_time_units exactly.
func adjTimeUnits(value float64) (float64, string) {
	if value == 0 {
		return 0, "s"
	}
	if value > 3600 {
		return value / 3600, "h"
	}
	if value > 60 {
		return value / 60, "m"
	}
	return value, "s"
}

// getSMH returns seconds, minutes, hours from total seconds.
func getSMH(totalSec float64) (int, int, int) {
	sec := int(totalSec)
	hr := sec / 3600
	sec -= hr * 3600
	min := sec / 60
	sec -= min * 60
	return sec, min, hr
}

// saidStringTrimmer trims "said:" prefixes iteratively.
// Matches Perl's said_string_trimmer exactly.
func saidStringTrimmer(s string, maxLen int) string {
	saidRe := regexp.MustCompile(`^.* said: `)
	colonRe := regexp.MustCompile(`^.*?: *`)

	for len(s) > maxLen {
		if saidRe.MatchString(s) {
			s = saidRe.ReplaceAllString(s, "")
		} else if colonRe.MatchString(s) {
			s = colonRe.ReplaceAllString(s, "")
		} else {
			s = s[:maxLen-3] + "..."
			break
		}
	}
	return s
}

// stringTrimmer truncates a string to maxLen with "..." if needed.
func stringTrimmer(s string, maxLen int, doNotTrim bool) string {
	if !doNotTrim && len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

// gimmeDomain extracts domain from host spec like "domain[ip]" or "domain/ip".
// Matches Perl's gimme_domain.
func gimmeDomain(hostSpec string) string {
	var domain, ipAddr string

	// Try "dom.ain[i.p.add.ress]"
	re1 := regexp.MustCompile(`^([^\[]+)\[((?:\d{1,3}\.){3}\d{1,3})\]`)
	if m := re1.FindStringSubmatch(hostSpec); m != nil {
		domain = m[1]
		ipAddr = m[2]
	} else {
		// Try "dom.ain/i.p.add.ress"
		re2 := regexp.MustCompile(`(?i)^([^/]+)/([0-9a-f.:]+)`)
		if m := re2.FindStringSubmatch(hostSpec); m != nil {
			domain = m[1]
			ipAddr = m[2]
		} else {
			// More exhaustive method
			re3 := regexp.MustCompile(`^([^\[\(/]+)[\[\(/]([^\]\)]+)[\]\)]?:?\s*$`)
			if m := re3.FindStringSubmatch(hostSpec); m != nil {
				domain = m[1]
				ipAddr = m[2]
			} else {
				// Can't parse - return as-is lowered
				return strings.TrimSpace(strings.ToLower(hostSpec))
			}
		}
	}

	if domain == "unknown" {
		return ipAddr
	}

	// Reduce "mach.host.dom" to "host.dom"
	domRe := regexp.MustCompile(`^(.*)\.([^.]+)\.([^.]{3}|[^.]{2,3}\.[^.]{2})$`)
	if m := domRe.FindStringSubmatch(domain); m != nil {
		domain = strings.ToLower(m[2] + "." + m[3])
	} else {
		domain = strings.ToLower(domain)
	}

	return domain
}

// verpMung applies VERP address munging.
func verpMung(addr string, verpMungVal int, verpMungEnabled bool) string {
	if !verpMungEnabled {
		return addr
	}

	// Simple munging: replace numeric IDs
	re1 := regexp.MustCompile(`(?i)((?:bounce[ds]?|no(?:list|reply|response)|return|sentto|\d+).*?)(?:[+_.*-]\d+\b)+`)
	addr = re1.ReplaceAllString(addr, "${1}-ID")

	// Aggressive munging
	if verpMungVal > 1 {
		re2 := regexp.MustCompile(`[*-](\d+[*-])?[^=*-]+[=*][^@]+@`)
		addr = re2.ReplaceAllString(addr, "@")
	}

	return addr
}

// normalizeHost normalizes an IP address or hostname for sorting.
func normalizeHost(host string) string {
	// Lop off possible " (user@dom.ain)" bit
	parts := strings.SplitN(host, " ", 2)
	norm1 := parts[0]

	// Check for dotted-quad IPv4 address
	ip := net.ParseIP(norm1)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			return string([]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		}
	}

	// Possibly hostname or user@dom.ain
	splitParts := strings.FieldsFunc(norm1, func(r rune) bool {
		return r == '.' || r == '@'
	})
	// Reverse and lowercase
	result := make([]string, len(splitParts))
	for i, p := range splitParts {
		result[len(splitParts)-1-i] = strings.ToLower(p)
	}
	return strings.Join(result, "")
}

// normalizeAddr normalizes an email address: lowercase domain part,
// or entire address if ignoreCase is set.
func normalizeAddr(addr string, ignoreCase bool) string {
	if ignoreCase {
		return strings.ToLower(addr)
	}
	// Only lowercase the domain part
	atIdx := strings.LastIndex(addr, "@")
	if atIdx >= 0 {
		return addr[:atIdx] + strings.ToLower(addr[atIdx:])
	}
	return addr
}

// uucpMung converts UUCP-style bang-paths.
func uucpMung(addr string) string {
	re := regexp.MustCompile(`^(.*!)*([^!]+)!([^!@]+)@([^.]+)$`)
	m := re.FindStringSubmatch(addr)
	if m == nil {
		return addr
	}
	prefix := m[1]
	host := m[2]
	user := m[3]
	nextHost := m[4]
	result := fmt.Sprintf("%s!", nextHost)
	if prefix != "" {
		result += prefix
	}
	result += fmt.Sprintf("%s@%s", user, host)
	return result
}
