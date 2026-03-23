package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var monthNames = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

var monthNums = map[string]int{
	"Jan": 0, "Feb": 1, "Mar": 2, "Apr": 3, "May": 4, "Jun": 5,
	"Jul": 6, "Aug": 7, "Sep": 8, "Oct": 9, "Nov": 10, "Dec": 11,
}

// Compiled regexps for log line parsing
var (
	// Traditional syslog: "Mon DD HH:MM:SS hostname remainder"
	reTrad = regexp.MustCompile(`^(...) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) \S+ (.+)$`)

	// RFC 3339: "YYYY-MM-DDTHH:MM:SS[.nnn][+-]HH:MM hostname remainder"
	reRFC3339 = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[+-](?:\d{2}):(?:\d{2})|Z) \S+ (.+)$`)

	// Solaris "[ID nnnnnn some.thing]" noise
	reIDNoise = regexp.MustCompile(`: \[ID \d+ [^\]]+\] `)

	// from=<addr>, size=N
	reFromSize = regexp.MustCompile(`from=<([^>]*)>, size=(\d+)`)

	// to=<addr>, relay=..., delay=..., status=...
	reToStatus = regexp.MustCompile(`to=<([^>]*)>, (?:orig_to=<[^>]*>, )?relay=([^,]+), (?:conn_use=[^,]+, )?delay=([^,]+), (?:delays=[^,]+, )?(?:dsn=[^,]+, )?status=(\S+)(.*)$`)

	// pickup sender/uid
	rePickup = regexp.MustCompile(`: (?:sender|uid)=`)

	// smtpd client=
	reSmtpdClient = regexp.MustCompile(`\[\d+\]: \w+: client=(.+?)(?:,|$)`)

	// smtpd reject/hold/discard
	reSmtpdReject = regexp.MustCompile(`\[\d+\]: \w+: (reject(?:_warning)?|hold|discard): `)

	// connect from
	reConnectFrom = regexp.MustCompile(`: connect from `)

	// disconnect from
	reDisconnectFrom = regexp.MustCompile(`/smtpd\[(\d+)\]: disconnect from (.+)$`)

	// smtpd PID extraction
	reSmtpdPID = regexp.MustCompile(`/smtpd\[(\d+)\]: `)

	// cleanup reject
	reCleanupReject = regexp.MustCompile(`/cleanup\[\d+\]: .*?\b(reject|warning|hold|discard): (header|body) (.*)$`)

	// smtp connect errors
	reSmtpConnect1 = regexp.MustCompile(`.* connect to (\S+?): ([^;]+); address \S+ port.*$`)
	reSmtpConnect2 = regexp.MustCompile(`.* connect to ([^\[]+)\[\S+?\]: (.+?) \(port \d+\)$`)

	// master daemon messages
	reMaster = regexp.MustCompile(`^.*master.*: (.+)$`)

	// MailScanner requeue
	reRequeue = regexp.MustCompile(`to (\w+)`)
)

// ParsedLine holds fields extracted from a log line.
type ParsedLine struct {
	MonStr   string
	Mon      int
	Day      int
	Hr       int
	Min      int
	Sec      int
	Year     int
	LogRmdr  string
	IsRFC    bool
}

// ParseTimestamp parses either traditional or RFC3339 timestamp from a line.
// Returns nil if the line doesn't match either format.
func ParseTimestamp(line string) *ParsedLine {
	// Try traditional syslog format
	if m := reTrad.FindStringSubmatch(line); m != nil {
		day, _ := strconv.Atoi(m[2])
		hr, _ := strconv.Atoi(m[3])
		min, _ := strconv.Atoi(m[4])
		sec, _ := strconv.Atoi(m[5])
		monStr := m[1]
		mon, ok := monthNums[monStr]
		if !ok {
			return nil
		}
		return &ParsedLine{
			MonStr:  monStr,
			Mon:     mon,
			Day:     day,
			Hr:      hr,
			Min:     min,
			Sec:     sec,
			Year:    guessYear(mon),
			LogRmdr: m[6],
			IsRFC:   false,
		}
	}

	// Try RFC 3339 format
	if m := reRFC3339.FindStringSubmatch(line); m != nil {
		yr, _ := strconv.Atoi(m[1])
		mon, _ := strconv.Atoi(m[2])
		day, _ := strconv.Atoi(m[3])
		hr, _ := strconv.Atoi(m[4])
		min, _ := strconv.Atoi(m[5])
		sec, _ := strconv.Atoi(m[6])
		return &ParsedLine{
			Mon:     mon - 1, // RFC 3339 months start at 1, we index from 0
			Day:     day,
			Hr:      hr,
			Min:     min,
			Sec:     sec,
			Year:    yr,
			LogRmdr: m[7],
			IsRFC:   true,
		}
	}

	return nil
}

// guessYear guesses the year for traditional syslog timestamps.
func guessYear(msgMon int) int {
	now := time.Now()
	year := now.Year()
	month := int(now.Month()) - 1 // 0-indexed
	if msgMon == 11 && month == 0 {
		year--
	}
	return year
}

// getDateStrs returns traditional and RFC3339 date filter strings.
func getDateStrs(dateOpt string) (string, string) {
	now := time.Now()
	t := now

	if dateOpt == "yesterday" {
		// Back up to yesterday: subtract (current_hour + 2) * 3600 seconds
		t = t.Add(-time.Duration((t.Hour()+2)*3600) * time.Second)
	}

	tMon := int(t.Month()) - 1 // 0-indexed
	return fmt.Sprintf("%s %2d", monthNames[tMon], t.Day()),
		fmt.Sprintf("%04d-%02d-%02d", t.Year(), t.Month(), t.Day())
}

// inTimeRange checks if a timestamp falls within the specified time range.
func inTimeRange(yr, mon, day, hr, min, sec int, timeRange [2]int64) bool {
	// mon is 0-indexed, time.Date expects 1-indexed month
	t := time.Date(yr, time.Month(mon+1), day, hr, min, sec, 0, time.Local)
	ts := t.Unix()
	return timeRange[0] < ts && ts < timeRange[1]
}

// buildPostfixRe builds the main command/qid extraction regexps.
func buildPostfixRe(syslogName string) []*regexp.Regexp {
	// Escape any regex special chars in syslogName
	escaped := regexp.QuoteMeta(syslogName)
	re1 := regexp.MustCompile(`^(?:postfix-?\w*|` + escaped + `)(?:/(?:smtps|submission))?/([^\[:]*)\b.*?: ([^:\s]+)`)
	re2 := regexp.MustCompile(`^((?:postfix)(?:-script)?)(?:\[\d+\])?: ([^:\s]+)`)
	re3 := regexp.MustCompile(`^MailScanner\[\d+\]: (Requeue): (\w+)\.`)
	return []*regexp.Regexp{re1, re2, re3}
}

// extractCmdQid extracts the command and queue ID from the log remainder.
func extractCmdQid(logRmdr string, cmdREs []*regexp.Regexp) (string, string, bool) {
	for _, re := range cmdREs {
		if m := re.FindStringSubmatch(logRmdr); m != nil {
			return m[1], m[2], true
		}
	}
	return "", "", false
}

// ProcessLine processes a single log line and updates stats.
func ProcessLine(line string, stats *Stats, opts *Options, cmdREs []*regexp.Regexp) {
	// Strip "[ID nnnnnn some.thing]" noise
	line = reIDNoise.ReplaceAllString(line, ": ")

	parsed := ParseTimestamp(line)
	if parsed == nil {
		return
	}

	// Apply date filter
	if opts.dateStr != "" {
		if !strings.HasPrefix(line, opts.dateStr+" ") && !strings.HasPrefix(line, opts.dateStrRFC3339+"T") {
			return
		}
	}

	// Apply time range filter
	if opts.hasTimeRange {
		if !inTimeRange(parsed.Year, parsed.Mon, parsed.Day, parsed.Hr, parsed.Min, parsed.Sec, opts.timeRange) {
			return
		}
	}

	logRmdr := parsed.LogRmdr

	// Extract command and queue ID
	cmd, qid, ok := extractCmdQid(logRmdr, cmdREs)
	if !ok {
		return
	}

	// Strip trailing newline/carriage return
	logRmdr = strings.TrimRight(logRmdr, "\r\n")

	// Year rollover check
	now := time.Now()
	thisMon := int(now.Month()) - 1
	thisYr := now.Year()
	if parsed.Mon > thisMon {
		parsed.Year = thisYr - 1
	} else {
		parsed.Year = thisYr
	}
	stats.MsgYr = parsed.Year

	// Day tracking
	if parsed.Day != stats.LastMsgDay {
		stats.LastMsgDay = parsed.Day
		stats.RevMsgDateStr = fmt.Sprintf("%d%02d%02d", parsed.Year, parsed.Mon, parsed.Day)
		stats.DayCnt++
		if opts.zeroFill {
			stats.ZeroFillDay(stats.RevMsgDateStr)
		}
	}

	// MailScanner requeue detection
	if cmd == "Requeue" {
		if m := reRequeue.FindStringSubmatch(logRmdr); m != nil {
			stats.Requeue[m[1]] = qid
		}
	}
	// Overload qid if MailScanner requeued
	if newQid, ok := stats.Requeue[qid]; ok {
		qid = newQid
	}

	// Process cleanup rejects
	if cmd == "cleanup" {
		if m := reCleanupReject.FindStringSubmatch(logRmdr); m != nil {
			rejSubTyp := m[1]
			rejReas := m[2]
			rejRmdr := m[3]

			if !opts.verbMsgDetail {
				// Strip " from <...>; from=<...>" stuff
				reFrom := regexp.MustCompile(`( from \S+?)?; from=<.*$`)
				rejRmdr = reFrom.ReplaceAllString(rejRmdr, "")
			}
			rejRmdr = stringTrimmer(rejRmdr, 64, opts.verbMsgDetail)

			switch rejSubTyp {
			case "reject":
				if opts.rejectDetail != 0 {
					stats.IncrRejects(stats.Rejects, cmd, rejReas, rejRmdr)
				}
				stats.MsgsRjctd++
			case "warning":
				if opts.rejectDetail != 0 {
					stats.IncrRejects(stats.Warns, cmd, rejReas, rejRmdr)
				}
				stats.MsgsWrnd++
			case "hold":
				if opts.rejectDetail != 0 {
					stats.IncrRejects(stats.Holds, cmd, rejReas, rejRmdr)
				}
				stats.MsgsHld++
			case "discard":
				if opts.rejectDetail != 0 {
					stats.IncrRejects(stats.Discards, cmd, rejReas, rejRmdr)
				}
				stats.MsgsDscrdd++
			}
			stats.RejPerHr[parsed.Hr]++
			stats.UpdateMsgsPerDay(stats.RevMsgDateStr, 4)
			return
		}
	}

	// Handle special qid values
	switch qid {
	case "warning":
		warnReas := logRmdr
		if idx := strings.Index(warnReas, "warning: "); idx >= 0 {
			warnReas = warnReas[idx+9:]
		}
		warnReas = stringTrimmer(warnReas, 66, opts.verbMsgDetail)
		if cmd == "smtpd" && opts.smtpdWarnDetail == 0 {
			return
		}
		IncrNested2(stats.Warnings, cmd, warnReas)
		return

	case "fatal":
		fatalReas := logRmdr
		if idx := strings.Index(fatalReas, "fatal: "); idx >= 0 {
			fatalReas = fatalReas[idx+7:]
		}
		fatalReas = stringTrimmer(fatalReas, 66, opts.verbMsgDetail)
		IncrNested2(stats.Fatals, cmd, fatalReas)
		return

	case "panic":
		panicReas := logRmdr
		if idx := strings.Index(panicReas, "panic: "); idx >= 0 {
			panicReas = panicReas[idx+7:]
		}
		panicReas = stringTrimmer(panicReas, 66, opts.verbMsgDetail)
		IncrNested2(stats.Panics, cmd, panicReas)
		return

	case "reject":
		procSmtpdReject(logRmdr, stats.Rejects, &stats.MsgsRjctd, &stats.RejPerHr[parsed.Hr], stats, opts)
		return

	case "reject_warning":
		procSmtpdReject(logRmdr, stats.Warns, &stats.MsgsWrnd, &stats.RejPerHr[parsed.Hr], stats, opts)
		return

	case "hold":
		procSmtpdReject(logRmdr, stats.Holds, &stats.MsgsHld, &stats.RejPerHr[parsed.Hr], stats, opts)
		return

	case "discard":
		procSmtpdReject(logRmdr, stats.Discards, &stats.MsgsDscrdd, &stats.RejPerHr[parsed.Hr], stats, opts)
		return
	}

	// Master daemon messages
	if cmd == "master" {
		if m := reMaster.FindStringSubmatch(logRmdr); m != nil {
			stats.MasterMsgs[m[1]]++
		}
		return
	}

	// SMTPD processing
	if cmd == "smtpd" {
		if m := reSmtpdClient.FindStringSubmatch(logRmdr); m != nil {
			// Message received via SMTP
			stats.RcvPerHr[parsed.Hr]++
			stats.UpdateMsgsPerDay(stats.RevMsgDateStr, 0)
			stats.MsgsRcvd++
			stats.RcvdMsg[qid] = gimmeDomain(m[1])
			return
		}

		if m := reSmtpdReject.FindStringSubmatch(logRmdr); m != nil {
			rejSubTyp := m[1]
			switch rejSubTyp {
			case "reject":
				procSmtpdReject(logRmdr, stats.Rejects, &stats.MsgsRjctd, &stats.RejPerHr[parsed.Hr], stats, opts)
			case "reject_warning":
				procSmtpdReject(logRmdr, stats.Warns, &stats.MsgsWrnd, &stats.RejPerHr[parsed.Hr], stats, opts)
			case "hold":
				procSmtpdReject(logRmdr, stats.Holds, &stats.MsgsHld, &stats.RejPerHr[parsed.Hr], stats, opts)
			case "discard":
				procSmtpdReject(logRmdr, stats.Discards, &stats.MsgsDscrdd, &stats.RejPerHr[parsed.Hr], stats, opts)
			}
			return
		}

		// SMTPD stats (connect/disconnect)
		if !opts.smtpdStats {
			return
		}

		if reConnectFrom.MatchString(logRmdr) {
			if m := reSmtpdPID.FindStringSubmatch(logRmdr); m != nil {
				pid := m[1]
				stats.ConnTime[pid] = &ConnTimeData{
					Year:  parsed.Year,
					Month: parsed.Mon + 1,
					Day:   parsed.Day,
					Hour:  parsed.Hr,
					Min:   parsed.Min,
					Sec:   parsed.Sec,
				}
			}
			return
		}

		if m := reDisconnectFrom.FindStringSubmatch(logRmdr); m != nil {
			pid := m[1]
			hostID := m[2]
			if ct, ok := stats.ConnTime[pid]; ok {
				hostID = gimmeDomain(hostID)

				// Calculate duration using Delta_DHMS equivalent
				t1 := time.Date(ct.Year, time.Month(ct.Month), ct.Day, ct.Hour, ct.Min, ct.Sec, 0, time.Local)
				t2 := time.Date(parsed.Year, time.Month(parsed.Mon+1), parsed.Day, parsed.Hr, parsed.Min, parsed.Sec, 0, time.Local)
				tSecs := t2.Sub(t1).Seconds()

				delete(stats.ConnTime, pid)

				// Per-hour
				stats.SmtpdPerHr[parsed.Hr].Count++
				stats.SmtpdPerHr[parsed.Hr].TotTime += tSecs
				if tSecs > stats.SmtpdPerHr[parsed.Hr].MaxTime {
					stats.SmtpdPerHr[parsed.Hr].MaxTime = tSecs
				}

				// Per-day
				if _, ok := stats.SmtpdPerDay[stats.RevMsgDateStr]; !ok {
					stats.SmtpdPerDay[stats.RevMsgDateStr] = &SmtpdDayData{}
				}
				stats.SmtpdPerDay[stats.RevMsgDateStr].Count++
				stats.SmtpdPerDay[stats.RevMsgDateStr].TotTime += tSecs
				if tSecs > stats.SmtpdPerDay[stats.RevMsgDateStr].MaxTime {
					stats.SmtpdPerDay[stats.RevMsgDateStr].MaxTime = tSecs
				}

				// Per-domain
				if _, ok := stats.SmtpdPerDom[hostID]; !ok {
					stats.SmtpdPerDom[hostID] = &SmtpdDomData{}
				}
				stats.SmtpdPerDom[hostID].Count++
				stats.SmtpdPerDom[hostID].TotTime += tSecs
				if tSecs > stats.SmtpdPerDom[hostID].MaxTime {
					stats.SmtpdPerDom[hostID].MaxTime = tSecs
				}

				stats.SmtpdConnCnt++
				stats.SmtpdTotTime += tSecs
			}
		}
		return
	}

	// Non-smtpd processing: from=, to=, pickup, smtp errors
	processMessageLine(logRmdr, cmd, qid, parsed, stats, opts)
}

// processMessageLine handles from=, to=, pickup lines and smtp errors.
func processMessageLine(logRmdr, cmd, qid string, parsed *ParsedLine, stats *Stats, opts *Options) {
	// from=<addr>, size=N
	if m := reFromSize.FindStringSubmatch(logRmdr); m != nil {
		addr := m[1]
		size, _ := strconv.Atoi(m[2])

		// Avoid double-counting
		if _, exists := stats.MsgSizes[qid]; exists {
			return
		}

		if addr != "" {
			if opts.uucpMung {
				addr = uucpMung(addr)
			}
			addr = normalizeAddr(addr, opts.ignoreCase)
			addr = verpMung(addr, opts.verpMungVal, opts.verpMung)
		} else {
			addr = "from=<>"
		}

		stats.MsgSizes[qid] = size

		if opts.extDetail {
			stats.MsgDetail[qid] = append(stats.MsgDetail[qid], addr)
		}

		// Avoid counting forwards
		if rcvdFrom, ok := stats.RcvdMsg[qid]; ok {
			// Get domain from sender address
			domAddr := addr
			atIdx := strings.Index(addr, "@")
			if atIdx >= 0 {
				domAddr = addr[atIdx+1:]
			} else {
				if rcvdFrom == "pickup" {
					domAddr = addr
				} else {
					domAddr = rcvdFrom
				}
			}

			sd := stats.EnsureSendgDom(domAddr)
			if sd.MsgCnt == 0 {
				stats.SendgDomCnt++
			}
			sd.MsgCnt++
			sd.MsgSize += size

			su := stats.EnsureSendgUser(addr)
			if su.MsgCnt == 0 {
				stats.SendgUserCnt++
			}
			su.MsgCnt++
			su.MsgSize += size

			stats.SizeRcvd += size
			delete(stats.RcvdMsg, qid)
		}
		return
	}

	// to=<addr>, relay=..., delay=..., status=...
	if m := reToStatus.FindStringSubmatch(logRmdr); m != nil {
		addr := m[1]
		relay := m[2]
		delayStr := m[3]
		status := m[4]
		toRmdr := m[5]

		delay, _ := strconv.ParseFloat(delayStr, 64)

		if opts.uucpMung {
			addr = uucpMung(addr)
		}
		addr = normalizeAddr(addr, opts.ignoreCase)
		if opts.ignoreCase {
			relay = strings.ToLower(relay)
		}

		// Get domain only
		domAddr := addr
		if atIdx := strings.Index(addr, "@"); atIdx >= 0 {
			domAddr = addr[atIdx+1:]
		}

		switch status {
		case "sent":
			// Was it actually forwarded?
			if strings.Contains(toRmdr, "forwarded as ") {
				stats.MsgsFwdd++
				return
			}

			rd := stats.EnsureRecipDom(domAddr)
			if rd.MsgCnt == 0 {
				stats.RecipDomCnt++
			}
			rd.MsgCnt++
			rd.DlyAvg += delay
			if delay > rd.DlyMax {
				rd.DlyMax = delay
			}

			ru := stats.EnsureRecipUser(addr)
			if ru.MsgCnt == 0 {
				stats.RecipUserCnt++
			}
			ru.MsgCnt++

			stats.DlvPerHr[parsed.Hr]++
			stats.UpdateMsgsPerDay(stats.RevMsgDateStr, 1)
			stats.MsgsDlvrd++

			if size, ok := stats.MsgSizes[qid]; ok {
				rd.MsgSize += size
				ru.MsgSize += size
				stats.SizeDlvrd += size
			} else {
				// No size data
				if !opts.noNoMsgSize {
					stats.NoMsgSize[qid] = addr
				}
				if opts.extDetail {
					stats.MsgDetail[qid] = append(stats.MsgDetail[qid], "(sender not in log)")
				}
			}

			if opts.extDetail {
				stats.MsgDetail[qid] = append(stats.MsgDetail[qid], addr)
			}

		case "deferred":
			if opts.deferralDetail != 0 {
				// Extract deferred reason
				re := regexp.MustCompile(`, status=deferred \(([^)]+)`)
				if rm := re.FindStringSubmatch(logRmdr); rm != nil {
					deferredReas := rm[1]
					if !opts.verbMsgDetail {
						deferredReas = saidStringTrimmer(deferredReas, 65)
						// Strip leading 3-digit code
						reCode := regexp.MustCompile(`^\d{3} `)
						deferredReas = reCode.ReplaceAllString(deferredReas, "")
						// Strip "connect to "
						deferredReas = strings.TrimPrefix(deferredReas, "connect to ")
					}
					IncrNested2(stats.Deferred, cmd, deferredReas)
				}
			}
			stats.DfrPerHr[parsed.Hr]++
			stats.UpdateMsgsPerDay(stats.RevMsgDateStr, 2)
			stats.MsgsDfrdCnt++
			if _, ok := stats.MsgDfrdFlg[qid]; !ok {
				stats.MsgDfrdFlg[qid] = 1
				stats.MsgsDfrd++
			} else {
				stats.MsgDfrdFlg[qid]++
			}
			rd := stats.EnsureRecipDom(domAddr)
			rd.Defers++
			if delay > rd.DlyMax {
				rd.DlyMax = delay
			}

		case "bounced":
			if opts.bounceDetail != 0 {
				re := regexp.MustCompile(`, status=bounced \((.+)\)`)
				if rm := re.FindStringSubmatch(logRmdr); rm != nil {
					bounceReas := rm[1]
					if !opts.verbMsgDetail {
						bounceReas = saidStringTrimmer(bounceReas, 66)
						reCode := regexp.MustCompile(`^\d{3} `)
						bounceReas = reCode.ReplaceAllString(bounceReas, "")
					}
					IncrNested2(stats.Bounced, relay, bounceReas)
				}
			}
			stats.BncPerHr[parsed.Hr]++
			stats.UpdateMsgsPerDay(stats.RevMsgDateStr, 3)
			stats.MsgsBncd++
		}
		return
	}

	// pickup: sender= or uid=
	if cmd == "pickup" && rePickup.MatchString(logRmdr) {
		stats.RcvPerHr[parsed.Hr]++
		stats.UpdateMsgsPerDay(stats.RevMsgDateStr, 0)
		stats.MsgsRcvd++
		stats.RcvdMsg[qid] = "pickup"
		return
	}

	// smtp connection errors
	if cmd == "smtp" && opts.smtpDetail != 0 {
		if m := reSmtpConnect1.FindStringSubmatch(logRmdr); m != nil {
			host := m[1]
			reason := strings.ToLower(m[2])
			IncrNested2(stats.SmtpMsgs, reason, host)
		} else if m := reSmtpConnect2.FindStringSubmatch(logRmdr); m != nil {
			host := m[1]
			reason := strings.ToLower(m[2])
			IncrNested2(stats.SmtpMsgs, reason, host)
		}
	}
}
