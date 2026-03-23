package main

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// Reject parsing regexps
	reRejectLine = regexp.MustCompile(`^.* \b(?:reject(?:_warning)?|hold|discard): (\S+) from (\S+?): (.*)$`)
	reRejToAddr  = regexp.MustCompile(`to=<([^>]+)>`)
	reRejToUnk   = regexp.MustCompile(`\d{3} <([^>]+)>: User unknown `)
	reRejToUnt   = regexp.MustCompile(`to=<(.*?)(?:[, ]|$)`)
	reRejFrom    = regexp.MustCompile(`from=<([^>]+)>`)

	// Reason trimming regexps
	reRejAngleBrackets = regexp.MustCompile(`^(\d{3} <).*?(>:)`)
	reRejSpecial1      = regexp.MustCompile(`^(?:.*?[:;] )(?:\[[^\]]+\] )?([^;,]+)[;,].*$`)
	reRejSenderRecip   = regexp.MustCompile(`^((?:Sender|Recipient) address rejected: [^:]+):.*$`)
	reRejBlocked       = regexp.MustCompile(`(Client host|Sender address) .+? blocked`)
	reRejMail          = regexp.MustCompile(`^\d{3} (?:<.+>: )?([^;:]+)[;:]?.*$`)
	reRejGeneric       = regexp.MustCompile(`^(?:.*[:;] )?([^,]+).*$`)

	// Specific reason patterns
	reRejSenderAddr  = regexp.MustCompile(`^Sender address rejected:`)
	reRejRecipAddr   = regexp.MustCompile(`^(Recipient address rejected:|User unknown( |$))`)
	reRejPipelining  = regexp.MustCompile(`^.*?\d{3} (Improper use of SMTP command pipelining);.*$`)
	reRejMsgSize     = regexp.MustCompile(`^.*?\d{3} (Message size exceeds fixed limit);.*$`)
	reRejServerConf  = regexp.MustCompile(`^.*?\d{3} (Server configuration (?:error|problem));.*$`)

	// Source extraction
	reRejSrc = regexp.MustCompile(`^.+? from (\S+?):.*$`)
)

// procSmtpdReject processes SMTPD reject/warning/hold/discard lines.
func procSmtpdReject(logLine string, rejects map[string]map[string]map[string]int, msgsRjctd *int, rejPerHr *int, stats *Stats, opts *Options) {
	*msgsRjctd++
	*rejPerHr++
	stats.UpdateMsgsPerDay(stats.RevMsgDateStr, 4)

	// Return early if not tracking reject detail
	if opts.rejectDetail == 0 {
		return
	}

	// Extract reject type, from host, and remainder
	m := reRejectLine.FindStringSubmatch(logLine)
	if m == nil {
		return
	}
	rejTyp := m[1]
	rejFrom := m[2]
	rejRmdr := m[3]

	// Get the reject reason
	rejReas := rejRmdr
	if !opts.verbMsgDetail {
		switch {
		case rejTyp == "RCPT" || rejTyp == "DATA" || rejTyp == "CONNECT":
			// Strip angle-bracketed content after reject code
			rejReas = reRejAngleBrackets.ReplaceAllString(rejReas, "${1}${2}")
			rejReas = reRejSpecial1.ReplaceAllString(rejReas, "$1")
			rejReas = reRejSenderRecip.ReplaceAllString(rejReas, "$1")
			rejReas = reRejBlocked.ReplaceAllString(rejReas, "blocked")
		case rejTyp == "MAIL":
			rejReas = reRejMail.ReplaceAllString(rejReas, "$1")
		default:
			rejReas = reRejGeneric.ReplaceAllString(rejReas, "$1")
		}
	}

	// Snag recipient address
	var to string
	if tm := reRejToAddr.FindStringSubmatch(rejRmdr); tm != nil {
		to = tm[1]
	} else if tm := reRejToUnk.FindStringSubmatch(rejRmdr); tm != nil {
		to = tm[1]
	} else if tm := reRejToUnt.FindStringSubmatch(rejRmdr); tm != nil {
		to = tm[1]
	} else {
		to = "<>"
	}
	if opts.ignoreCase {
		to = strings.ToLower(to)
	}

	// Snag sender address
	var from string
	if fm := reRejFrom.FindStringSubmatch(rejRmdr); fm != nil {
		from = fm[1]
	} else {
		from = "<>"
	}

	rejAddFrom := false
	if from != "" {
		rejAddFrom = opts.rejAddFrom
		from = verpMung(from, opts.verpMungVal, opts.verpMung)
		if opts.ignoreCase {
			from = strings.ToLower(from)
		}
	}

	// Ensure maps exist
	if _, ok := rejects[rejTyp]; !ok {
		rejects[rejTyp] = make(map[string]map[string]int)
	}
	if _, ok := rejects[rejTyp][rejReas]; !ok {
		rejects[rejTyp][rejReas] = make(map[string]int)
	}

	// Stash in triple-subscripted hash
	if reRejSenderAddr.MatchString(rejReas) {
		rejects[rejTyp][rejReas][from]++
	} else if reRejRecipAddr.MatchString(rejReas) {
		rejData := to
		if rejAddFrom {
			if from != "" && from != "<>" {
				rejData += fmt.Sprintf("  (%s)", from)
			} else {
				rejData += fmt.Sprintf("  (%s)", gimmeDomain(rejFrom))
			}
		}
		rejects[rejTyp][rejReas][rejData]++
	} else if m := reRejPipelining.FindStringSubmatch(rejReas); m != nil {
		rejReas = m[1]
		// Ensure map exists for new rejReas
		if _, ok := rejects[rejTyp][rejReas]; !ok {
			rejects[rejTyp][rejReas] = make(map[string]int)
		}
		if sm := reRejSrc.FindStringSubmatch(logLine); sm != nil {
			rejects[rejTyp][rejReas][sm[1]]++
		}
	} else if m := reRejMsgSize.FindStringSubmatch(rejReas); m != nil {
		rejReas = m[1]
		if _, ok := rejects[rejTyp][rejReas]; !ok {
			rejects[rejTyp][rejReas] = make(map[string]int)
		}
		rejData := gimmeDomain(rejFrom)
		if rejAddFrom {
			rejData += fmt.Sprintf("  (%s)", from)
		}
		rejects[rejTyp][rejReas][rejData]++
	} else if m := reRejServerConf.FindStringSubmatch(rejReas); m != nil {
		rejReas = "(Local) " + m[1]
		if _, ok := rejects[rejTyp][rejReas]; !ok {
			rejects[rejTyp][rejReas] = make(map[string]int)
		}
		rejData := gimmeDomain(rejFrom)
		if rejAddFrom {
			rejData += fmt.Sprintf("  (%s)", from)
		}
		rejects[rejTyp][rejReas][rejData]++
	} else {
		rejData := gimmeDomain(rejFrom)
		if rejAddFrom {
			rejData += fmt.Sprintf("  (%s)", from)
		}
		rejects[rejTyp][rejReas][rejData]++
	}
}
