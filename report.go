package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// printSubsectTitle prints a section title with underline.
func printSubsectTitle(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
}

// printGrandTotals prints the grand totals section.
func printGrandTotals(stats *Stats, opts *Options) {
	// Calculate reject and discard percentages
	msgsRjctdPct := 0
	msgsDscrddPct := 0
	msgsTotal := stats.MsgsDlvrd + stats.MsgsRjctd + stats.MsgsDscrdd
	if msgsTotal > 0 {
		msgsRjctdPct = int(float64(stats.MsgsRjctd) / float64(msgsTotal) * 100)
		msgsDscrddPct = int(float64(stats.MsgsDscrdd) / float64(msgsTotal) * 100)
	}

	if opts.dateStr != "" {
		fmt.Printf("Postfix log summaries for %s\n", opts.dateStr)
	}

	printSubsectTitle("Grand Totals")
	fmt.Print("messages\n\n")

	v, u := adjIntUnits(stats.MsgsRcvd)
	fmt.Printf(" %6d%s  received\n", v, u)
	v, u = adjIntUnits(stats.MsgsDlvrd)
	fmt.Printf(" %6d%s  delivered\n", v, u)
	v, u = adjIntUnits(stats.MsgsFwdd)
	fmt.Printf(" %6d%s  forwarded\n", v, u)
	v, u = adjIntUnits(stats.MsgsDfrd)
	fmt.Printf(" %6d%s  deferred", v, u)
	if stats.MsgsDfrdCnt > 0 {
		v2, u2 := adjIntUnits(stats.MsgsDfrdCnt)
		fmt.Printf("  (%d%s deferrals)", v2, u2)
	}
	fmt.Println()
	v, u = adjIntUnits(stats.MsgsBncd)
	fmt.Printf(" %6d%s  bounced\n", v, u)
	v, u = adjIntUnits(stats.MsgsRjctd)
	fmt.Printf(" %6d%s  rejected (%d%%)\n", v, u, msgsRjctdPct)
	v, u = adjIntUnits(stats.MsgsWrnd)
	fmt.Printf(" %6d%s  reject warnings\n", v, u)
	v, u = adjIntUnits(stats.MsgsHld)
	fmt.Printf(" %6d%s  held\n", v, u)
	v, u = adjIntUnits(stats.MsgsDscrdd)
	fmt.Printf(" %6d%s  discarded (%d%%)\n", v, u, msgsDscrddPct)
	fmt.Println()
	v, u = adjIntUnits(stats.SizeRcvd)
	fmt.Printf(" %6d%s  bytes received\n", v, u)
	v, u = adjIntUnits(stats.SizeDlvrd)
	fmt.Printf(" %6d%s  bytes delivered\n", v, u)
	v, u = adjIntUnits(stats.SendgUserCnt)
	fmt.Printf(" %6d%s  senders\n", v, u)
	v, u = adjIntUnits(stats.SendgDomCnt)
	fmt.Printf(" %6d%s  sending hosts/domains\n", v, u)
	v, u = adjIntUnits(stats.RecipUserCnt)
	fmt.Printf(" %6d%s  recipients\n", v, u)
	v, u = adjIntUnits(stats.RecipDomCnt)
	fmt.Printf(" %6d%s  recipient hosts/domains\n", v, u)

	if opts.smtpdStats {
		fmt.Print("\nsmtpd\n\n")
		v, u = adjIntUnits(stats.SmtpdConnCnt)
		fmt.Printf("  %6d%s  connections\n", v, u)
		v, u = adjIntUnits(len(stats.SmtpdPerDom))
		fmt.Printf("  %6d%s  hosts/domains\n", v, u)
		avgConn := 0
		if stats.SmtpdConnCnt > 0 {
			avgConn = int(stats.SmtpdTotTime/float64(stats.SmtpdConnCnt) + 0.5)
		}
		fmt.Printf("  %6d   avg. connect time (seconds)\n", avgConn)
		sec, min, hr := getSMH(stats.SmtpdTotTime)
		fmt.Printf(" %2d:%02d:%02d  total connect time\n", hr, min, sec)
	}

	fmt.Println()
}

// printPerDaySummary prints the per-day traffic summary.
func printPerDaySummary(stats *Stats, opts *Options) {
	if stats.DayCnt <= 1 {
		return
	}

	printSubsectTitle("Per-Day Traffic Summary")
	fmt.Println("    date          received  delivered   deferred    bounced     rejected")
	fmt.Println("    --------------------------------------------------------------------")

	keys := make([]string, 0, len(stats.MsgsPerDay))
	for k := range stats.MsgsPerDay {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		data := stats.MsgsPerDay[k]
		// Unpack YYYYMMDD
		var msgYr, msgMon, msgDay int
		fmt.Sscanf(k, "%4d%2d%2d", &msgYr, &msgMon, &msgDay)
		if opts.isoDateTime {
			fmt.Printf("    %04d-%02d-%02d ", msgYr, msgMon+1, msgDay)
		} else {
			monStr := monthNames[msgMon]
			fmt.Printf("    %s %2d %d", monStr, msgDay, msgYr)
		}
		for _, val := range data {
			v, u := adjIntUnits(val)
			fmt.Printf("    %6d%s", v, u)
		}
		fmt.Println()
	}
}

// printPerHourSummary prints the per-hour traffic summary.
func printPerHourSummary(stats *Stats, opts *Options) {
	reportType := "Summary"
	if stats.DayCnt > 1 {
		reportType = "Daily Average"
	}

	printSubsectTitle(fmt.Sprintf("Per-Hour Traffic %s", reportType))
	fmt.Println("    time          received  delivered   deferred    bounced     rejected")
	fmt.Println("    --------------------------------------------------------------------")

	for hour := 0; hour < 24; hour++ {
		if opts.isoDateTime {
			fmt.Printf("    %02d:00-%02d:00", hour, hour+1)
		} else {
			fmt.Printf("    %02d00-%02d00  ", hour, hour+1)
		}

		values := [5]int{stats.RcvPerHr[hour], stats.DlvPerHr[hour], stats.DfrPerHr[hour], stats.BncPerHr[hour], stats.RejPerHr[hour]}
		for _, val := range values {
			displayVal := val
			if stats.DayCnt > 0 {
				displayVal = int(float64(val)/float64(stats.DayCnt) + 0.5)
			}
			v, u := adjIntUnits(displayVal)
			fmt.Printf("    %6d%s", v, u)
		}
		fmt.Println()
	}
}

// printRecipDomainSummary prints the host/domain delivery summary.
func printRecipDomainSummary(stats *Stats, cnt int) {
	if cnt == 0 {
		return
	}
	topCnt := ""
	if cnt > 0 {
		topCnt = fmt.Sprintf("(top %d)", cnt)
	}

	printSubsectTitle(fmt.Sprintf("Host/Domain Summary: Message Delivery %s", topCnt))
	fmt.Println(" sent cnt  bytes   defers   avg dly max dly host/domain")
	fmt.Println(" -------- -------  -------  ------- ------- -----------")

	// Sort by count desc, then size desc
	type domEntry struct {
		name string
		data *DomainData
	}
	entries := make([]domEntry, 0, len(stats.RecipDom))
	for name, data := range stats.RecipDom {
		entries = append(entries, domEntry{name, data})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].data.MsgCnt != entries[j].data.MsgCnt {
			return entries[i].data.MsgCnt > entries[j].data.MsgCnt
		}
		return entries[i].data.MsgSize > entries[j].data.MsgSize
	})

	printed := 0
	for _, e := range entries {
		avgDly := 0.0
		if e.data.MsgCnt > 0 {
			avgDly = e.data.DlyAvg / float64(e.data.MsgCnt)
		}

		cv, cu := adjIntUnits(e.data.MsgCnt)
		sv, su := adjIntUnits(e.data.MsgSize)
		dv, du := adjIntUnits(e.data.Defers)
		av, au := adjTimeUnits(avgDly)
		mv, mu := adjTimeUnits(e.data.DlyMax)

		fmt.Printf(" %6d%s  %6d%s  %6d%s  %5.1f %s  %5.1f %s  %s\n",
			cv, cu, sv, su, dv, du, av, au, mv, mu, e.name)

		printed++
		if cnt > 0 && printed >= cnt {
			break
		}
	}
}

// printSendingDomainSummary prints the host/domain received summary.
func printSendingDomainSummary(stats *Stats, cnt int) {
	if cnt == 0 {
		return
	}
	topCnt := ""
	if cnt > 0 {
		topCnt = fmt.Sprintf("(top %d)", cnt)
	}

	printSubsectTitle(fmt.Sprintf("Host/Domain Summary: Messages Received %s", topCnt))
	fmt.Println(" msg cnt   bytes   host/domain")
	fmt.Println(" -------- -------  -----------")

	type domEntry struct {
		name string
		data *DomainData
	}
	entries := make([]domEntry, 0, len(stats.SendgDom))
	for name, data := range stats.SendgDom {
		entries = append(entries, domEntry{name, data})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].data.MsgCnt != entries[j].data.MsgCnt {
			return entries[i].data.MsgCnt > entries[j].data.MsgCnt
		}
		return entries[i].data.MsgSize > entries[j].data.MsgSize
	})

	printed := 0
	for _, e := range entries {
		cv, cu := adjIntUnits(e.data.MsgCnt)
		sv, su := adjIntUnits(e.data.MsgSize)
		fmt.Printf(" %6d%s  %6d%s  %s\n", cv, cu, sv, su, e.name)

		printed++
		if cnt > 0 && printed >= cnt {
			break
		}
	}
}

// printUserData prints user data sorted in descending order.
func printUserData(hashRef map[string]*DomainData, title string, useSize bool, cnt int, quiet bool) {
	if cnt == 0 {
		return
	}
	fullTitle := title
	if cnt > 0 {
		fullTitle = fmt.Sprintf("top %d %s", cnt, title)
	}

	if len(hashRef) == 0 {
		if quiet {
			return
		}
		fmt.Printf("\n%s: none\n", fullTitle)
		return
	}

	fmt.Printf("\n%s\n%s\n", fullTitle, strings.Repeat("-", len(fullTitle)))

	type userEntry struct {
		name string
		val  int
		norm string
	}

	entries := make([]userEntry, 0, len(hashRef))
	for name, data := range hashRef {
		val := data.MsgCnt
		if useSize {
			val = data.MsgSize
		}
		entries = append(entries, userEntry{name, val, normalizeHost(name)})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].val != entries[j].val {
			return entries[i].val > entries[j].val
		}
		return entries[i].norm < entries[j].norm
	})

	printed := 0
	for _, e := range entries {
		v, u := adjIntUnits(e.val)
		fmt.Printf(" %6d%s  %s\n", v, u, e.name)
		printed++
		if cnt > 0 && printed >= cnt {
			break
		}
	}
}

// printNestedHash prints a nested hash structure.
func printNestedHash(hashRef map[string]map[string]int, title string, cnt int, quiet bool) {
	if len(hashRef) == 0 {
		if quiet {
			return
		}
		fmt.Printf("\n%s: none\n", title)
		return
	}

	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
	walkNestedHash2(hashRef, cnt, 2)
}

// printTripleNestedHash prints a triple-nested hash structure.
func printTripleNestedHash(hashRef map[string]map[string]map[string]int, title string, cnt int, quiet bool) {
	if len(hashRef) == 0 {
		if quiet {
			return
		}
		fmt.Printf("\n%s: none\n", title)
		return
	}

	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))

	// Sort outer keys
	outerKeys := make([]string, 0, len(hashRef))
	for k := range hashRef {
		outerKeys = append(outerKeys, k)
	}
	sort.Strings(outerKeys)

	for _, outerKey := range outerKeys {
		innerHash := hashRef[outerKey]
		fmt.Printf("  %s", outerKey)

		// Check if this level has data totals
		total := 0
		for _, subHash := range innerHash {
			for _, v := range subHash {
				total += v
			}
		}
		if cnt > 0 {
			fmt.Printf(" (top %d)", cnt)
		}
		fmt.Printf(" (total: %d)", total)
		fmt.Println()

		// Sort and print inner keys with their data
		innerKeys := make([]string, 0, len(innerHash))
		for k := range innerHash {
			innerKeys = append(innerKeys, k)
		}
		sort.Strings(innerKeys)

		for _, innerKey := range innerKeys {
			dataHash := innerHash[innerKey]
			fmt.Printf("    %s", innerKey)

			// Total for this sub-category
			subTotal := 0
			for _, v := range dataHash {
				subTotal += v
			}
			if cnt > 0 {
				fmt.Printf(" (top %d)", cnt)
			}
			fmt.Printf(" (total: %d)", subTotal)
			fmt.Println()

			// Print the data sorted by count
			reallyPrintHashByCntVals(dataHash, cnt, "      ")
		}
	}
}

// walkNestedHash2 walks and prints a double-nested hash.
func walkNestedHash2(hashRef map[string]map[string]int, cnt int, level int) {
	// Sort outer keys
	keys := make([]string, 0, len(hashRef))
	for k := range hashRef {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	indents := strings.Repeat(" ", level)

	for _, key := range keys {
		innerHash := hashRef[key]
		fmt.Printf("%s%s", indents, key)

		// Total the counts
		total := 0
		for _, v := range innerHash {
			total += v
		}

		if cnt > 0 {
			fmt.Printf(" (top %d)", cnt)
		}
		fmt.Printf(" (total: %d)", total)
		fmt.Println()

		reallyPrintHashByCntVals(innerHash, cnt, indents+"  ")
	}
}

// reallyPrintHashByCntVals prints hash contents sorted by count desc, then by normalized host asc.
func reallyPrintHashByCntVals(hashRef map[string]int, cnt int, indents string) {
	type entry struct {
		key  string
		val  int
		norm string
	}

	entries := make([]entry, 0, len(hashRef))
	for k, v := range hashRef {
		entries = append(entries, entry{k, v, normalizeHost(k)})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].val != entries[j].val {
			return entries[i].val > entries[j].val
		}
		return entries[i].norm < entries[j].norm
	})

	printed := 0
	for _, e := range entries {
		v, u := adjIntUnits(e.val)
		fmt.Printf("%s%6d%s  %s\n", indents, v, u, e.key)
		printed++
		if cnt > 0 && printed >= cnt {
			break
		}
	}
}

// printHashByKey prints hash contents sorted by key ascending.
func printHashByKey(hashRef map[string]string, title string, cnt int, quiet bool) {
	fullTitle := title
	if cnt > 0 {
		fullTitle = fmt.Sprintf("first %d %s", cnt, title)
	}

	if len(hashRef) == 0 {
		if quiet {
			return
		}
		fmt.Printf("\n%s: none\n", fullTitle)
		return
	}

	fmt.Printf("\n%s\n%s\n", fullTitle, strings.Repeat("-", len(fullTitle)))

	keys := make([]string, 0, len(hashRef))
	for k := range hashRef {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	printed := 0
	for _, k := range keys {
		fmt.Printf(" %s  %s\n", k, hashRef[k])
		printed++
		if cnt > 0 && printed >= cnt {
			break
		}
	}
}

// printHashByCntVals prints hash contents sorted by count desc.
func printHashByCntVals(hashRef map[string]int, title string, cnt int, quiet bool) {
	fullTitle := title
	if cnt > 0 {
		fullTitle = fmt.Sprintf("top %d %s", cnt, title)
	}

	if len(hashRef) == 0 {
		if quiet {
			return
		}
		fmt.Printf("\n%s: none\n", fullTitle)
		return
	}

	fmt.Printf("\n%s\n%s\n", fullTitle, strings.Repeat("-", len(fullTitle)))
	reallyPrintHashByCntVals(hashRef, cnt, " ")
}

// printProblemsReports prints all problem reports.
func printProblemsReports(stats *Stats, opts *Options) {
	if opts.deferralDetail != 0 {
		printNestedHash(stats.Deferred, "message deferral detail", opts.deferralDetail, opts.quiet)
	}
	if opts.bounceDetail != 0 {
		printNestedHash(stats.Bounced, "message bounce detail (by relay)", opts.bounceDetail, opts.quiet)
	}
	if opts.rejectDetail != 0 {
		printTripleNestedHash(stats.Rejects, "message reject detail", opts.rejectDetail, opts.quiet)
		printTripleNestedHash(stats.Warns, "message reject warning detail", opts.rejectDetail, opts.quiet)
		printTripleNestedHash(stats.Holds, "message hold detail", opts.rejectDetail, opts.quiet)
		printTripleNestedHash(stats.Discards, "message discard detail", opts.rejectDetail, opts.quiet)
	}
	if opts.smtpDetail != 0 {
		printNestedHash(stats.SmtpMsgs, "smtp delivery failures", opts.smtpDetail, opts.quiet)
	}
	if opts.smtpdWarnDetail != 0 {
		printNestedHash(stats.Warnings, "Warnings", opts.smtpdWarnDetail, opts.quiet)
	}
	printNestedHash(stats.Fatals, "Fatal Errors", 0, opts.quiet)
	printNestedHash(stats.Panics, "Panics", 0, opts.quiet)
	printHashByCntVals(stats.MasterMsgs, "Master daemon messages", 0, opts.quiet)
}

// printDetailedMsgData prints per-message detail (with -e flag).
func printDetailedMsgData(stats *Stats, title string, quiet bool) {
	hashRef := stats.MsgDetail

	if len(hashRef) == 0 {
		if quiet {
			return
		}
		fmt.Printf("\n%s: none\n", title)
		return
	}

	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))

	// Sort by domain then user
	type msgEntry struct {
		qid      string
		sender   string
		domain   string
		userName string
	}

	entries := make([]msgEntry, 0, len(hashRef))
	for qid, addrs := range hashRef {
		sender := ""
		if len(addrs) > 0 {
			sender = addrs[0]
		}
		// Extract domain and user for sorting
		userName, domainName := extractUserDomain(sender)
		// Reorder domain for sorting
		domainName = reorderDomain(domainName)
		entries = append(entries, msgEntry{qid, sender, domainName, userName})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].domain != entries[j].domain {
			return entries[i].domain < entries[j].domain
		}
		if entries[i].userName != entries[j].userName {
			return entries[i].userName < entries[j].userName
		}
		return entries[i].qid < entries[j].qid
	})

	for _, e := range entries {
		addrs := hashRef[e.qid]
		if len(addrs) == 0 {
			continue
		}
		fmt.Printf(" %s  %s\n", e.qid, addrs[0])
		for _, addr := range addrs[1:] {
			fmt.Printf("   %s\n", addr)
		}
		fmt.Println()
	}
}

// extractUserDomain splits an address into user and domain parts.
func extractUserDomain(addr string) (string, string) {
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	// Try UUCP-style
	bangParts := strings.Split(addr, "!")
	if len(bangParts) >= 2 {
		return bangParts[len(bangParts)-1], bangParts[len(bangParts)-2]
	}
	return addr, ""
}

// reorderDomain reorders "mach.host.dom" to "host.dom.mach" for sorting.
func reorderDomain(domain string) string {
	if domain == "" {
		return ""
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		return domain
	}
	// Try to match the Perl pattern: ^(.*)\.([^.]+)\.([^.]{3}|[^.]{2,3}\.[^.]{2})$
	// Simplified: just reverse for sorting
	last := parts[len(parts)-1]
	secondLast := parts[len(parts)-2]
	if len(last) == 2 && len(parts) >= 3 {
		// Country code TLD like .co.uk
		if len(parts) >= 4 {
			thirdLast := parts[len(parts)-3]
			rest := strings.Join(parts[:len(parts)-3], ".")
			return thirdLast + "." + secondLast + "." + last + "." + rest
		}
	}
	if len(last) == 3 || (len(last) >= 2 && len(last) <= 3) {
		rest := strings.Join(parts[:len(parts)-2], ".")
		return secondLast + "." + last + "." + rest
	}
	return domain
}

// printMailq runs the mailq command and prints its output.
func printMailq() {
	printSubsectTitle("Current Mail Queue")
	cmd := exec.Command("mailq")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// printAllReports prints all reports in proper order.
func printAllReports(stats *Stats, opts *Options) {
	printGrandTotals(stats, opts)

	if opts.problemsFirst {
		printProblemsReports(stats, opts)
	}

	printPerDaySummary(stats, opts)
	printPerHourSummary(stats, opts)

	printRecipDomainSummary(stats, opts.h)
	printSendingDomainSummary(stats, opts.h)

	if opts.smtpdStats {
		printPerDaySmtpd(stats, opts)
		printPerHourSmtpd(stats, opts)
		printDomainSmtpdSummary(stats, opts.h)
	}

	printUserData(stats.SendgUser, "Senders by message count", false, opts.u, opts.quiet)
	printUserData(stats.RecipUser, "Recipients by message count", false, opts.u, opts.quiet)
	printUserData(stats.SendgUser, "Senders by message size", true, opts.u, opts.quiet)
	printUserData(stats.RecipUser, "Recipients by message size", true, opts.u, opts.quiet)

	printHashByKey(stats.NoMsgSize, "Messages with no size data", 0, true)

	if !opts.problemsFirst {
		printProblemsReports(stats, opts)
	}

	if opts.extDetail {
		printDetailedMsgData(stats, "Message detail", opts.quiet)
	}

	if opts.mailq {
		printMailq()
	}
}

// printPerDaySmtpd prints the per-day SMTPD connection summary.
func printPerDaySmtpd(stats *Stats, opts *Options) {
	if stats.DayCnt <= 1 {
		return
	}

	printSubsectTitle("Per-Day SMTPD Connection Summary")
	fmt.Println("    date        connections    time conn.    avg./conn.   max. time")
	fmt.Println("    --------------------------------------------------------------------")

	keys := make([]string, 0, len(stats.SmtpdPerDay))
	for k := range stats.SmtpdPerDay {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		data := stats.SmtpdPerDay[k]
		var msgYr, msgMon, msgDay int
		fmt.Sscanf(k, "%4d%2d%2d", &msgYr, &msgMon, &msgDay)
		if opts.isoDateTime {
			fmt.Printf("    %04d-%02d-%02d ", msgYr, msgMon+1, msgDay)
		} else {
			monStr := monthNames[msgMon]
			fmt.Printf("    %s %2d %d", monStr, msgDay, msgYr)
		}

		avg := int(float64(data.TotTime)/float64(data.Count) + 0.5)
		sec, min, hr := getSMH(data.TotTime)

		cv, cu := adjIntUnits(data.Count)
		fmt.Printf("   %6d%s       %2d:%02d:%02d      %6ds      %6ds\n",
			cv, cu, hr, min, sec, avg, int(data.MaxTime))
	}
}

// printPerHourSmtpd prints the per-hour SMTPD connection summary.
func printPerHourSmtpd(stats *Stats, opts *Options) {
	if stats.DayCnt > 1 {
		printSubsectTitle("Per-Hour SMTPD Connection Daily Average")
		fmt.Println("    hour        connections    time conn.")
		fmt.Println("    -------------------------------------")
	} else {
		printSubsectTitle("Per-Hour SMTPD Connection Summary")
		fmt.Println("    hour        connections    time conn.    avg./conn.   max. time")
		fmt.Println("    --------------------------------------------------------------------")
	}

	for hour := 0; hour < 24; hour++ {
		if stats.SmtpdPerHr[hour].Count == 0 {
			continue
		}

		count := float64(stats.SmtpdPerHr[hour].Count)
		totTime := stats.SmtpdPerHr[hour].TotTime
		avg := 0
		if count > 0 {
			avg = int(totTime/count + 0.5)
		}

		if stats.DayCnt > 1 {
			count = count/float64(stats.DayCnt) + 0.5
			totTime = totTime/float64(stats.DayCnt) + 0.5
		}

		sec, min, hr := getSMH(totTime)

		if opts.isoDateTime {
			fmt.Printf("    %02d:00-%02d:00", hour, hour+1)
		} else {
			fmt.Printf("    %02d00-%02d00  ", hour, hour+1)
		}

		cv, cu := adjIntUnits(int(count))
		fmt.Printf("   %6d%s       %2d:%02d:%02d", cv, cu, hr, min, sec)

		if stats.DayCnt < 2 {
			fmt.Printf("      %6ds      %6ds", avg, int(stats.SmtpdPerHr[hour].MaxTime))
		}
		fmt.Println()
	}
}

// printDomainSmtpdSummary prints the per-domain SMTPD connection summary.
func printDomainSmtpdSummary(stats *Stats, cnt int) {
	if cnt == 0 {
		return
	}
	topCnt := ""
	if cnt > 0 {
		topCnt = fmt.Sprintf("(top %d)", cnt)
	}

	printSubsectTitle(fmt.Sprintf("Host/Domain Summary: SMTPD Connections %s", topCnt))
	fmt.Println(" connections  time conn.  avg./conn.  max. time  host/domain")
	fmt.Println(" -----------  ----------  ----------  ---------  -----------")

	type domEntry struct {
		name string
		data *SmtpdDomData
	}
	entries := make([]domEntry, 0, len(stats.SmtpdPerDom))
	for name, data := range stats.SmtpdPerDom {
		entries = append(entries, domEntry{name, data})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].data.Count != entries[j].data.Count {
			return entries[i].data.Count > entries[j].data.Count
		}
		return entries[i].data.TotTime > entries[j].data.TotTime
	})

	printed := 0
	for _, e := range entries {
		avg := int(e.data.TotTime/float64(e.data.Count) + 0.5)
		sec, min, hr := getSMH(e.data.TotTime)

		cv, cu := adjIntUnits(e.data.Count)
		fmt.Printf("  %6d%s      %2d:%02d:%02d     %6ds    %6ds   %s\n",
			cv, cu, hr, min, sec, avg, int(e.data.MaxTime), e.name)

		printed++
		if cnt > 0 && printed >= cnt {
			break
		}
	}
}
