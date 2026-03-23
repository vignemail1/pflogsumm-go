package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const version = "1.1.5"

// Options holds all command-line options.
type Options struct {
	bounceDetail   int
	deferralDetail int
	rejectDetail   int
	smtpDetail     int
	smtpdWarnDetail int
	h              int
	u              int
	detail         int
	detailSet      bool

	dateOpt        string
	dateStr        string
	dateStrRFC3339 string

	hasTimeRange   bool
	timeRange      [2]int64

	extDetail      bool
	ignoreCase     bool
	isoDateTime    bool
	uucpMung       bool
	mailq          bool
	noNoMsgSize    bool
	problemsFirst  bool
	rejAddFrom     bool
	quiet          bool
	smtpdStats     bool
	verbMsgDetail  bool
	verpMung       bool
	verpMungVal    int
	zeroFill       bool

	syslogName     string

	showHelp       bool
	showVersion    bool

	files          []string
}

var usageMsg = `usage: pflogsumm -[eq] [-d <today|yesterday>] [--detail <cnt>]
	[--bounce-detail <cnt>] [--deferral-detail <cnt>]
	[-h <cnt>] [-i|--ignore-case] [--iso-date-time] [--mailq]
	[-m|--uucp-mung] [--no-no-msg-size] [--problems-first]
	[--rej-add-from] [--reject-detail <cnt>] [--smtp-detail <cnt>]
	[--smtpd-stats] [--smtpd-warning-detail <cnt>]
	[--syslog-name=string] [-u <cnt>] [--verbose-msg-detail]
	[--verp-mung[=<n>]] [--zero-fill] [file1 [filen]]

       pflogsumm --[version|help]`

func main() {
	opts := parseArgs(os.Args[1:])

	if opts.showHelp {
		fmt.Println(usageMsg)
		os.Exit(0)
	}

	if opts.showVersion {
		fmt.Printf("pflogsumm %s\n", version)
		os.Exit(0)
	}

	// Set up date filter strings
	if opts.dateOpt != "" {
		if opts.dateOpt != "today" && opts.dateOpt != "yesterday" {
			fmt.Fprintln(os.Stderr, usageMsg)
			os.Exit(1)
		}
		opts.dateStr, opts.dateStrRFC3339 = getDateStrs(opts.dateOpt)
	}

	stats := NewStats()
	syslogName := opts.syslogName
	if syslogName == "" {
		syslogName = "postfix"
	}
	cmdREs := buildPostfixRe(syslogName)

	// Process input
	if len(opts.files) == 0 {
		processReader(os.Stdin, stats, opts, cmdREs)
	} else {
		for _, fname := range opts.files {
			f, err := os.Open(fname)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pflogsumm: %s: %v\n", fname, err)
				continue
			}
			processReader(f, stats, opts, cmdREs)
			f.Close()
		}
	}

	printAllReports(stats, opts)
}

func processReader(r io.Reader, stats *Stats, opts *Options, cmdREs []*regexp.Regexp) {
	scanner := bufio.NewScanner(r)
	// Increase buffer size for very long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		ProcessLine(scanner.Text(), stats, opts, cmdREs)
	}
}

func parseArgs(args []string) *Options {
	opts := &Options{
		bounceDetail:   -1,
		deferralDetail: -1,
		rejectDetail:   -1,
		smtpDetail:     -1,
		smtpdWarnDetail: -1,
		h:              -1,
		u:              -1,
		detail:         -1,
	}

	// Normalize underscores to dashes in --switches
	for i := range args {
		if strings.HasPrefix(args[i], "--") {
			args[i] = strings.ReplaceAll(args[i], "_", "-")
		}
	}

	i := 0
	for i < len(args) {
		arg := args[i]

		switch {
		case arg == "--bounce-detail":
			i++
			if i < len(args) {
				opts.bounceDetail, _ = strconv.Atoi(args[i])
			}
		case arg == "-d":
			i++
			if i < len(args) {
				opts.dateOpt = args[i]
			}
		case arg == "--time-range":
			if i+2 < len(args) {
				opts.hasTimeRange = true
				opts.timeRange[0], _ = strconv.ParseInt(args[i+1], 10, 64)
				opts.timeRange[1], _ = strconv.ParseInt(args[i+2], 10, 64)
				i += 2
			}
		case arg == "--deferral-detail":
			i++
			if i < len(args) {
				opts.deferralDetail, _ = strconv.Atoi(args[i])
			}
		case arg == "--detail":
			i++
			if i < len(args) {
				opts.detail, _ = strconv.Atoi(args[i])
				opts.detailSet = true
			}
		case arg == "-e":
			opts.extDetail = true
		case arg == "--help":
			opts.showHelp = true
		case arg == "-h":
			i++
			if i < len(args) {
				opts.h, _ = strconv.Atoi(args[i])
			}
		case arg == "-i" || arg == "--ignore-case":
			opts.ignoreCase = true
		case arg == "--iso-date-time":
			opts.isoDateTime = true
		case arg == "-m" || arg == "--uucp-mung":
			opts.uucpMung = true
		case arg == "--mailq":
			opts.mailq = true
		case arg == "--no-bounce-detail":
			opts.bounceDetail = 0
			fmt.Fprintf(os.Stderr, "pflogsumm: \"no_bounce_detail\" is deprecated, use \"bounce-detail=0\" instead\n")
		case arg == "--no-deferral-detail":
			opts.deferralDetail = 0
			fmt.Fprintf(os.Stderr, "pflogsumm: \"no_deferral_detail\" is deprecated, use \"deferral-detail=0\" instead\n")
		case arg == "--no-reject-detail":
			opts.rejectDetail = 0
			fmt.Fprintf(os.Stderr, "pflogsumm: \"no_reject_detail\" is deprecated, use \"reject-detail=0\" instead\n")
		case arg == "--no-smtpd-warnings":
			opts.smtpdWarnDetail = 0
			fmt.Fprintf(os.Stderr, "pflogsumm: \"no_smtpd_warnings\" is deprecated, use \"smtpd-warning-detail=0\" instead\n")
		case arg == "--no-no-msg-size":
			opts.noNoMsgSize = true
		case arg == "--problems-first":
			opts.problemsFirst = true
		case arg == "--rej-add-from":
			opts.rejAddFrom = true
		case arg == "-q":
			opts.quiet = true
		case arg == "--reject-detail":
			i++
			if i < len(args) {
				opts.rejectDetail, _ = strconv.Atoi(args[i])
			}
		case arg == "--smtp-detail":
			i++
			if i < len(args) {
				opts.smtpDetail, _ = strconv.Atoi(args[i])
			}
		case arg == "--smtpd-stats":
			opts.smtpdStats = true
		case arg == "--smtpd-warning-detail":
			i++
			if i < len(args) {
				opts.smtpdWarnDetail, _ = strconv.Atoi(args[i])
			}
		case strings.HasPrefix(arg, "--syslog-name="):
			opts.syslogName = strings.TrimPrefix(arg, "--syslog-name=")
		case arg == "--syslog-name":
			i++
			if i < len(args) {
				opts.syslogName = args[i]
			}
		case arg == "-u":
			i++
			if i < len(args) {
				opts.u, _ = strconv.Atoi(args[i])
			}
		case arg == "--verbose-msg-detail":
			opts.verbMsgDetail = true
		case strings.HasPrefix(arg, "--verp-mung"):
			opts.verpMung = true
			if strings.Contains(arg, "=") {
				valStr := arg[strings.Index(arg, "=")+1:]
				opts.verpMungVal, _ = strconv.Atoi(valStr)
			} else {
				opts.verpMungVal = 1
			}
		case arg == "--version":
			opts.showVersion = true
		case arg == "--zero-fill":
			opts.zeroFill = true
		case arg == "--":
			// Everything after -- is a filename
			opts.files = append(opts.files, args[i+1:]...)
			i = len(args)
			continue
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(os.Stderr, "pflogsumm: unknown option: %s\n", arg)
			fmt.Fprintln(os.Stderr, usageMsg)
			os.Exit(1)
		default:
			opts.files = append(opts.files, arg)
		}
		i++
	}

	// Apply --detail default: -1 (undefined) means "all" (20 for display)
	// If --detail was specified, set anything that wasn't individually set
	if opts.detailSet {
		if opts.h == -1 {
			opts.h = opts.detail
		}
		if opts.u == -1 {
			opts.u = opts.detail
		}
		if opts.bounceDetail == -1 {
			opts.bounceDetail = opts.detail
		}
		if opts.deferralDetail == -1 {
			opts.deferralDetail = opts.detail
		}
		if opts.smtpDetail == -1 {
			opts.smtpDetail = opts.detail
		}
		if opts.smtpdWarnDetail == -1 {
			opts.smtpdWarnDetail = opts.detail
		}
		if opts.rejectDetail == -1 {
			opts.rejectDetail = opts.detail
		}
	}

	// Set defaults: -1 means "show all" (equivalent to 20 in Perl)
	if opts.h == -1 {
		opts.h = 20
	}
	if opts.u == -1 {
		opts.u = 20
	}
	if opts.bounceDetail == -1 {
		opts.bounceDetail = 20
	}
	if opts.deferralDetail == -1 {
		opts.deferralDetail = 20
	}
	if opts.smtpDetail == -1 {
		opts.smtpDetail = 20
	}
	if opts.smtpdWarnDetail == -1 {
		opts.smtpdWarnDetail = 20
	}
	if opts.rejectDetail == -1 {
		opts.rejectDetail = 20
	}

	return opts
}
