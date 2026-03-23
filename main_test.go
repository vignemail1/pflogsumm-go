package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// --- Unit Tests for utils.go ---

func TestAdjIntUnits(t *testing.T) {
	tests := []struct {
		input    int
		wantVal  int
		wantUnit string
	}{
		{0, 0, " "},
		{100, 100, " "},
		{524288, 524288, " "},     // exactly at boundary - not exceeded
		{524289, 512, "k"},        // just over 512k
		{1048576, 1024, "k"},      // 1MB in bytes
		{536870912, 524288, "k"},  // exactly at mega boundary
		{536870913, 512, "m"},     // just over 512m
	}
	for _, tt := range tests {
		v, u := adjIntUnits(tt.input)
		if v != tt.wantVal || u != tt.wantUnit {
			t.Errorf("adjIntUnits(%d) = (%d, %q), want (%d, %q)",
				tt.input, v, u, tt.wantVal, tt.wantUnit)
		}
	}
}

func TestAdjTimeUnits(t *testing.T) {
	tests := []struct {
		input    float64
		wantUnit string
	}{
		{0, "s"},
		{30, "s"},
		{60, "s"},     // exactly 60 - not exceeded
		{61, "m"},     // > 60 becomes minutes
		{3600, "m"},   // exactly 3600 - not exceeded (60m)
		{3601, "h"},   // > 3600 becomes hours
	}
	for _, tt := range tests {
		_, u := adjTimeUnits(tt.input)
		if u != tt.wantUnit {
			t.Errorf("adjTimeUnits(%f) unit = %q, want %q", tt.input, u, tt.wantUnit)
		}
	}
}

func TestGetSMH(t *testing.T) {
	tests := []struct {
		input            float64
		wantSec, wantMin, wantHr int
	}{
		{0, 0, 0, 0},
		{61, 1, 1, 0},
		{3661, 1, 1, 1},
		{86400, 0, 0, 24},
	}
	for _, tt := range tests {
		s, m, h := getSMH(tt.input)
		if s != tt.wantSec || m != tt.wantMin || h != tt.wantHr {
			t.Errorf("getSMH(%f) = (%d,%d,%d), want (%d,%d,%d)",
				tt.input, s, m, h, tt.wantSec, tt.wantMin, tt.wantHr)
		}
	}
}

func TestStringTrimmer(t *testing.T) {
	tests := []struct {
		input     string
		maxLen    int
		doNotTrim bool
		want      string
	}{
		{"short", 10, false, "short"},
		{"a very long string that should be trimmed", 20, false, "a very long strin..."},
		{"a very long string that should not be trimmed", 20, true, "a very long string that should not be trimmed"},
	}
	for _, tt := range tests {
		got := stringTrimmer(tt.input, tt.maxLen, tt.doNotTrim)
		if got != tt.want {
			t.Errorf("stringTrimmer(%q, %d, %v) = %q, want %q",
				tt.input, tt.maxLen, tt.doNotTrim, got, tt.want)
		}
	}
}

func TestSaidStringTrimmer(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"host said: 450 temporary failure", 30, "450 temporary failure"},
		{"very long string without said prefix that exceeds the maximum allowed length limit set", 40, "very long string without said prefix ..."},
	}
	for _, tt := range tests {
		got := saidStringTrimmer(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("saidStringTrimmer(%q, %d) = %q, want %q",
				tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestGimmeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"mail.example.com[192.168.1.1]", "example.com"},
		{"unknown[10.0.0.1]", "10.0.0.1"},
		{"host.sub.example.com[192.168.1.1]", "example.com"},
		{"mx.example.co.uk[192.168.1.1]", "example.co.uk"},
	}
	for _, tt := range tests {
		got := gimmeDomain(tt.input)
		if got != tt.want {
			t.Errorf("gimmeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeAddr(t *testing.T) {
	tests := []struct {
		input      string
		ignoreCase bool
		want       string
	}{
		{"User@EXAMPLE.COM", false, "User@example.com"},
		{"User@EXAMPLE.COM", true, "user@example.com"},
		{"noatsign", false, "noatsign"},
	}
	for _, tt := range tests {
		got := normalizeAddr(tt.input, tt.ignoreCase)
		if got != tt.want {
			t.Errorf("normalizeAddr(%q, %v) = %q, want %q",
				tt.input, tt.ignoreCase, got, tt.want)
		}
	}
}

func TestVerpMung(t *testing.T) {
	tests := []struct {
		addr    string
		val     int
		enabled bool
		want    string
	}{
		{"list-return-36-user=dom.com@lists.example.com", 1, true, "list-return-ID-user=dom.com@lists.example.com"},
		{"list-return-36-user=dom.com@lists.example.com", 2, true, "list-return-ID@lists.example.com"},
		{"normal@example.com", 1, true, "normal@example.com"},
		{"list-return-36-user=dom.com@lists.example.com", 1, false, "list-return-36-user=dom.com@lists.example.com"},
	}
	for _, tt := range tests {
		got := verpMung(tt.addr, tt.val, tt.enabled)
		if got != tt.want {
			t.Errorf("verpMung(%q, %d, %v) = %q, want %q",
				tt.addr, tt.val, tt.enabled, got, tt.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"192.168.1.1"},
		{"mail.example.com"},
		{"user@example.com"},
	}
	for _, tt := range tests {
		got := normalizeHost(tt.input)
		if got == "" {
			t.Errorf("normalizeHost(%q) returned empty string", tt.input)
		}
	}
}

// --- Unit Tests for parser.go ---

func TestParseTimestampTraditional(t *testing.T) {
	line := "Mar 22 08:30:45 mailhost postfix/smtpd[12345]: ABCDE: client=foo[1.2.3.4]"
	p := ParseTimestamp(line)
	if p == nil {
		t.Fatal("ParseTimestamp returned nil for traditional format")
	}
	if p.Mon != 2 { // March = index 2
		t.Errorf("Month = %d, want 2", p.Mon)
	}
	if p.Day != 22 {
		t.Errorf("Day = %d, want 22", p.Day)
	}
	if p.Hr != 8 {
		t.Errorf("Hour = %d, want 8", p.Hr)
	}
	if p.Min != 30 {
		t.Errorf("Min = %d, want 30", p.Min)
	}
	if p.Sec != 45 {
		t.Errorf("Sec = %d, want 45", p.Sec)
	}
	if p.IsRFC {
		t.Error("IsRFC should be false for traditional format")
	}
	if !strings.Contains(p.LogRmdr, "postfix/smtpd") {
		t.Errorf("LogRmdr = %q, should contain 'postfix/smtpd'", p.LogRmdr)
	}
}

func TestParseTimestampRFC3339(t *testing.T) {
	line := "2024-03-22T08:30:45.123+00:00 mailhost postfix/smtpd[12345]: ABCDE: client=foo[1.2.3.4]"
	p := ParseTimestamp(line)
	if p == nil {
		t.Fatal("ParseTimestamp returned nil for RFC3339 format")
	}
	if p.Year != 2024 {
		t.Errorf("Year = %d, want 2024", p.Year)
	}
	if p.Mon != 2 { // March = index 2 (0-indexed)
		t.Errorf("Month = %d, want 2", p.Mon)
	}
	if p.Day != 22 {
		t.Errorf("Day = %d, want 22", p.Day)
	}
	if !p.IsRFC {
		t.Error("IsRFC should be true for RFC3339 format")
	}
}

func TestParseTimestampRFC3339Z(t *testing.T) {
	line := "2024-03-22T08:30:45Z mailhost postfix/smtpd[12345]: ABCDE: client=foo[1.2.3.4]"
	p := ParseTimestamp(line)
	if p == nil {
		t.Fatal("ParseTimestamp returned nil for RFC3339 Z format")
	}
	if p.Year != 2024 {
		t.Errorf("Year = %d, want 2024", p.Year)
	}
}

func TestParseTimestampInvalid(t *testing.T) {
	line := "this is not a valid log line"
	p := ParseTimestamp(line)
	if p != nil {
		t.Error("ParseTimestamp should return nil for invalid line")
	}
}

func TestParseTimestampSingleDigitDay(t *testing.T) {
	line := "Mar  2 08:30:45 mailhost postfix/smtpd[12345]: ABCDE: client=foo[1.2.3.4]"
	p := ParseTimestamp(line)
	if p == nil {
		t.Fatal("ParseTimestamp returned nil for single-digit day")
	}
	if p.Day != 2 {
		t.Errorf("Day = %d, want 2", p.Day)
	}
}

func TestExtractCmdQid(t *testing.T) {
	cmdREs := buildPostfixRe("postfix")

	tests := []struct {
		input   string
		wantCmd string
		wantQid string
		wantOK  bool
	}{
		{"postfix/smtpd[12345]: ABCDE12345: client=foo", "smtpd", "ABCDE12345", true},
		{"postfix/qmgr[12347]: ABCDE12345: from=<user@example.com>", "qmgr", "ABCDE12345", true},
		{"postfix/smtp[12348]: ABCDE12345: to=<user@example.com>", "smtp", "ABCDE12345", true},
		{"postfix/cleanup[12346]: ABCDE12345: message-id=<msg@example.com>", "cleanup", "ABCDE12345", true},
		{"postfix/pickup[12360]: KLMNO11111: uid=1000", "pickup", "KLMNO11111", true},
		{"postfix-script[12345]: starting the Postfix", "postfix-script", "starting", true},
		{"not a postfix line", "", "", false},
	}
	for _, tt := range tests {
		cmd, qid, ok := extractCmdQid(tt.input, cmdREs)
		if ok != tt.wantOK {
			t.Errorf("extractCmdQid(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			continue
		}
		if ok && (cmd != tt.wantCmd || qid != tt.wantQid) {
			t.Errorf("extractCmdQid(%q) = (%q, %q), want (%q, %q)",
				tt.input, cmd, qid, tt.wantCmd, tt.wantQid)
		}
	}
}

// --- Unit tests for options parsing ---

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		check func(*Options) bool
	}{
		{"help", []string{"--help"}, func(o *Options) bool { return o.showHelp }},
		{"version", []string{"--version"}, func(o *Options) bool { return o.showVersion }},
		{"quiet", []string{"-q"}, func(o *Options) bool { return o.quiet }},
		{"extDetail", []string{"-e"}, func(o *Options) bool { return o.extDetail }},
		{"ignoreCase", []string{"-i"}, func(o *Options) bool { return o.ignoreCase }},
		{"ignoreCaseLong", []string{"--ignore-case"}, func(o *Options) bool { return o.ignoreCase }},
		{"isoDateTime", []string{"--iso-date-time"}, func(o *Options) bool { return o.isoDateTime }},
		{"smtpdStats", []string{"--smtpd-stats"}, func(o *Options) bool { return o.smtpdStats }},
		{"problemsFirst", []string{"--problems-first"}, func(o *Options) bool { return o.problemsFirst }},
		{"uucpMung", []string{"-m"}, func(o *Options) bool { return o.uucpMung }},
		{"uucpMungLong", []string{"--uucp-mung"}, func(o *Options) bool { return o.uucpMung }},
		{"mailq", []string{"--mailq"}, func(o *Options) bool { return o.mailq }},
		{"zeroFill", []string{"--zero-fill"}, func(o *Options) bool { return o.zeroFill }},
		{"rejAddFrom", []string{"--rej-add-from"}, func(o *Options) bool { return o.rejAddFrom }},
		{"noNoMsgSize", []string{"--no-no-msg-size"}, func(o *Options) bool { return o.noNoMsgSize }},
		{"verbMsgDetail", []string{"--verbose-msg-detail"}, func(o *Options) bool { return o.verbMsgDetail }},
		{"dateToday", []string{"-d", "today"}, func(o *Options) bool { return o.dateOpt == "today" }},
		{"dateYesterday", []string{"-d", "yesterday"}, func(o *Options) bool { return o.dateOpt == "yesterday" }},
		{"hFlag", []string{"-h", "10"}, func(o *Options) bool { return o.h == 10 }},
		{"uFlag", []string{"-u", "5"}, func(o *Options) bool { return o.u == 5 }},
		{"bounceDetail", []string{"--bounce-detail", "15"}, func(o *Options) bool { return o.bounceDetail == 15 }},
		{"deferralDetail", []string{"--deferral-detail", "0"}, func(o *Options) bool { return o.deferralDetail == 0 }},
		{"rejectDetail", []string{"--reject-detail", "25"}, func(o *Options) bool { return o.rejectDetail == 25 }},
		{"smtpDetail", []string{"--smtp-detail", "30"}, func(o *Options) bool { return o.smtpDetail == 30 }},
		{"smtpdWarnDetail", []string{"--smtpd-warning-detail", "0"}, func(o *Options) bool { return o.smtpdWarnDetail == 0 }},
		{"syslogNameEq", []string{"--syslog-name=mypostfix"}, func(o *Options) bool { return o.syslogName == "mypostfix" }},
		{"syslogNameSp", []string{"--syslog-name", "mypostfix"}, func(o *Options) bool { return o.syslogName == "mypostfix" }},
		{"verpMung", []string{"--verp-mung"}, func(o *Options) bool { return o.verpMung && o.verpMungVal == 1 }},
		{"verpMung2", []string{"--verp-mung=2"}, func(o *Options) bool { return o.verpMung && o.verpMungVal == 2 }},
		{"detailSetsAll", []string{"--detail", "50"}, func(o *Options) bool {
			return o.h == 50 && o.u == 50 && o.bounceDetail == 50 && o.deferralDetail == 50
		}},
		{"detailOverridden", []string{"--detail", "50", "-h", "10"}, func(o *Options) bool {
			return o.h == 10 && o.u == 50
		}},
		{"files", []string{"file1.log", "file2.log"}, func(o *Options) bool {
			return len(o.files) == 2 && o.files[0] == "file1.log" && o.files[1] == "file2.log"
		}},
		{"underscoreNormalize", []string{"--bounce_detail", "5"}, func(o *Options) bool {
			return o.bounceDetail == 5
		}},
		{"timeRange", []string{"--time-range", "1000", "2000"}, func(o *Options) bool {
			return o.hasTimeRange && o.timeRange[0] == 1000 && o.timeRange[1] == 2000
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := parseArgs(tt.args)
			if !tt.check(opts) {
				t.Errorf("parseArgs(%v) did not produce expected result", tt.args)
			}
		})
	}
}

func TestParseArgsDefaults(t *testing.T) {
	opts := parseArgs([]string{})
	if opts.h != 20 {
		t.Errorf("default h = %d, want 20", opts.h)
	}
	if opts.u != 20 {
		t.Errorf("default u = %d, want 20", opts.u)
	}
	if opts.bounceDetail != 20 {
		t.Errorf("default bounceDetail = %d, want 20", opts.bounceDetail)
	}
	if opts.deferralDetail != 20 {
		t.Errorf("default deferralDetail = %d, want 20", opts.deferralDetail)
	}
	if opts.rejectDetail != 20 {
		t.Errorf("default rejectDetail = %d, want 20", opts.rejectDetail)
	}
	if opts.smtpDetail != 20 {
		t.Errorf("default smtpDetail = %d, want 20", opts.smtpDetail)
	}
	if opts.smtpdWarnDetail != 20 {
		t.Errorf("default smtpdWarnDetail = %d, want 20", opts.smtpdWarnDetail)
	}
}

// --- Integration test ---

func TestIntegrationSampleLog(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	stats := NewStats()
	opts := parseArgs([]string{})
	cmdREs := buildPostfixRe("postfix")

	f, err := os.Open("testdata/sample.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	processReader(f, stats, opts, cmdREs)

	// Verify stats
	if stats.MsgsRcvd != 4 {
		t.Errorf("MsgsRcvd = %d, want 4", stats.MsgsRcvd)
	}
	if stats.MsgsDlvrd != 5 {
		t.Errorf("MsgsDlvrd = %d, want 5", stats.MsgsDlvrd)
	}
	if stats.MsgsBncd != 1 {
		t.Errorf("MsgsBncd = %d, want 1", stats.MsgsBncd)
	}
	if stats.MsgsDfrd != 1 {
		t.Errorf("MsgsDfrd = %d, want 1", stats.MsgsDfrd)
	}
	if stats.MsgsRjctd != 1 {
		t.Errorf("MsgsRjctd = %d, want 1", stats.MsgsRjctd)
	}
	if stats.SendgUserCnt != 4 {
		t.Errorf("SendgUserCnt = %d, want 4", stats.SendgUserCnt)
	}

	// Print the report to verify no panics
	printAllReports(stats, opts)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains expected sections
	expectedSections := []string{
		"Grand Totals",
		"Per-Hour Traffic",
		"Host/Domain Summary: Message Delivery",
		"Host/Domain Summary: Messages Received",
		"Senders by message count",
		"Recipients by message count",
		"Senders by message size",
		"Recipients by message size",
	}
	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("Output missing section: %q", section)
		}
	}

	// Verify grand totals numbers
	if !strings.Contains(output, "received") {
		t.Error("Output missing 'received' count")
	}
	if !strings.Contains(output, "delivered") {
		t.Error("Output missing 'delivered' count")
	}
}

func TestIntegrationRFC3339Log(t *testing.T) {
	stats := NewStats()
	opts := parseArgs([]string{})
	cmdREs := buildPostfixRe("postfix")

	f, err := os.Open("testdata/rfc3339.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	processReader(f, stats, opts, cmdREs)

	if stats.MsgsRcvd != 1 {
		t.Errorf("MsgsRcvd = %d, want 1", stats.MsgsRcvd)
	}
	if stats.MsgsDlvrd != 1 {
		t.Errorf("MsgsDlvrd = %d, want 1", stats.MsgsDlvrd)
	}
}

func TestIntegrationSmtpdStats(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	stats := NewStats()
	opts := parseArgs([]string{"--smtpd-stats"})
	cmdREs := buildPostfixRe("postfix")

	f, err := os.Open("testdata/sample.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	processReader(f, stats, opts, cmdREs)
	printAllReports(stats, opts)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "connections") {
		t.Error("Output missing smtpd 'connections' section")
	}
	if !strings.Contains(output, "SMTPD Connection") {
		t.Error("Output missing SMTPD Connection summary")
	}
}

func TestIntegrationQuietMode(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	stats := NewStats()
	opts := parseArgs([]string{"-q"})
	cmdREs := buildPostfixRe("postfix")

	// Process empty input
	processReader(strings.NewReader(""), stats, opts, cmdREs)
	printAllReports(stats, opts)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// In quiet mode, empty reports should not have headings
	// "Grand Totals" should still appear
	if !strings.Contains(output, "Grand Totals") {
		t.Error("Quiet mode should still print Grand Totals")
	}
}

func TestIntegrationISODateTime(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	stats := NewStats()
	opts := parseArgs([]string{"--iso-date-time"})
	cmdREs := buildPostfixRe("postfix")

	f, err := os.Open("testdata/sample.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	processReader(f, stats, opts, cmdREs)
	printAllReports(stats, opts)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// ISO format uses HH:MM-HH:MM instead of HHMM-HHMM
	if !strings.Contains(output, "08:00-09:00") && !strings.Contains(output, "00:00-01:00") {
		t.Error("ISO date time format not found in per-hour output")
	}
}

func TestInTimeRange(t *testing.T) {
	tests := []struct {
		yr, mon, day, hr, min, sec int
		start, end                 int64
		want                       bool
	}{
		{2024, 2, 22, 8, 0, 0, 1700000000, 1700001000, false}, // Outside range (Nov 2023 range)
	}
	for _, tt := range tests {
		got := inTimeRange(tt.yr, tt.mon, tt.day, tt.hr, tt.min, tt.sec, [2]int64{tt.start, tt.end})
		if got != tt.want {
			t.Errorf("inTimeRange(...) = %v, want %v", got, tt.want)
		}
	}
}

// Test uucpMung
func TestUucpMung(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"somehost.dom!user@foo", "foo!user@somehost.dom"},
		{"normal@example.com", "normal@example.com"},
	}
	for _, tt := range tests {
		got := uucpMung(tt.input)
		if got != tt.want {
			t.Errorf("uucpMung(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// Test guessYear
func TestGuessYear(t *testing.T) {
	yr := guessYear(2) // March
	if yr <= 2020 || yr > 2030 {
		t.Errorf("guessYear(2) = %d, unexpected year", yr)
	}
}

// Test NewStats
func TestNewStats(t *testing.T) {
	s := NewStats()
	if s.SendgUser == nil || s.RecipUser == nil || s.MsgSizes == nil {
		t.Error("NewStats() returned nil maps")
	}
}

// Test EnsureDom functions
func TestEnsureDomFunctions(t *testing.T) {
	s := NewStats()

	rd := s.EnsureRecipDom("example.com")
	if rd == nil {
		t.Fatal("EnsureRecipDom returned nil")
	}
	rd.MsgCnt = 5
	rd2 := s.EnsureRecipDom("example.com")
	if rd2.MsgCnt != 5 {
		t.Error("EnsureRecipDom did not return existing entry")
	}

	sd := s.EnsureSendgDom("sender.com")
	if sd == nil {
		t.Fatal("EnsureSendgDom returned nil")
	}

	su := s.EnsureSendgUser("user@sender.com")
	if su == nil {
		t.Fatal("EnsureSendgUser returned nil")
	}

	ru := s.EnsureRecipUser("user@recip.com")
	if ru == nil {
		t.Fatal("EnsureRecipUser returned nil")
	}
}

// Test processing with no input
func TestProcessEmptyInput(t *testing.T) {
	stats := NewStats()
	opts := parseArgs([]string{})
	cmdREs := buildPostfixRe("postfix")

	processReader(strings.NewReader(""), stats, opts, cmdREs)

	if stats.MsgsRcvd != 0 || stats.MsgsDlvrd != 0 {
		t.Error("Empty input should produce zero stats")
	}
}
