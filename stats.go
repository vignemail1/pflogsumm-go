package main

// DomainData holds per-domain statistics.
// Indexes: [0]=msgCount, [1]=msgSize, [2]=deferrals, [3]=delayTotal(for avg), [4]=delayMax
type DomainData struct {
	MsgCnt  int
	MsgSize int
	Defers  int
	DlyAvg  float64 // total delay for averaging
	DlyMax  float64 // max delay
}

// SmtpdDomData holds per-domain SMTPD connection data.
type SmtpdDomData struct {
	Count   int
	TotTime float64
	MaxTime float64
}

// SmtpdHourData holds per-hour SMTPD connection data.
type SmtpdHourData struct {
	Count   int
	TotTime float64
	MaxTime float64
}

// SmtpdDayData holds per-day SMTPD connection data.
type SmtpdDayData struct {
	Count   int
	TotTime float64
	MaxTime float64
}

// ConnTimeData tracks SMTPD connection start times.
type ConnTimeData struct {
	Year, Month, Day, Hour, Min, Sec int
}

// Stats holds all the statistics collected during log processing.
type Stats struct {
	// Grand totals
	MsgsRcvd    int
	MsgsDlvrd   int
	MsgsFwdd    int
	MsgsDfrd    int // unique deferred messages
	MsgsDfrdCnt int // total deferrals
	MsgsBncd    int
	MsgsRjctd   int
	MsgsWrnd    int
	MsgsHld     int
	MsgsDscrdd  int
	SizeRcvd    int
	SizeDlvrd   int

	// User data
	SendgUser    map[string]*DomainData
	SendgUserCnt int
	RecipUser    map[string]*DomainData
	RecipUserCnt int

	// Domain data
	SendgDom    map[string]*DomainData
	SendgDomCnt int
	RecipDom    map[string]*DomainData
	RecipDomCnt int

	// Per-hour stats
	RcvPerHr [24]int
	DlvPerHr [24]int
	DfrPerHr [24]int
	BncPerHr [24]int
	RejPerHr [24]int

	// Per-day stats
	MsgsPerDay map[string][5]int // key=YYYYMMDD, values=[rcvd,dlvrd,dfrd,bncd,rjctd]
	DayCnt     int
	LastMsgDay int

	// Tracking maps
	MsgSizes   map[string]int    // qid -> size
	RcvdMsg    map[string]string // qid -> source domain
	MsgDfrdFlg map[string]int    // qid -> deferred flag (for unique counting)
	NoMsgSize  map[string]string // qid -> addr
	MsgDetail  map[string][]string

	// Nested hash data for problem reports
	Deferred map[string]map[string]int    // cmd -> reason -> count
	Bounced  map[string]map[string]int    // relay -> reason -> count
	Rejects  map[string]map[string]map[string]int // type -> reason -> addr -> count
	Warns    map[string]map[string]map[string]int
	Holds    map[string]map[string]map[string]int
	Discards map[string]map[string]map[string]int
	SmtpMsgs map[string]map[string]int    // failure -> host -> count

	// Warning/error/etc
	Warnings   map[string]map[string]int // cmd -> reason -> count
	Fatals     map[string]map[string]int
	Panics     map[string]map[string]int
	MasterMsgs map[string]int

	// SMTPD stats
	SmtpdPerHr  [24]SmtpdHourData
	SmtpdPerDay map[string]*SmtpdDayData
	SmtpdPerDom map[string]*SmtpdDomData
	SmtpdConnCnt int
	SmtpdTotTime float64
	ConnTime     map[string]*ConnTimeData // pid -> connect time

	// Requeue tracking (MailScanner)
	Requeue map[string]string

	// Current message date tracking
	RevMsgDateStr string
	MsgYr         int
}

// NewStats creates a new Stats with all maps initialized.
func NewStats() *Stats {
	return &Stats{
		SendgUser:    make(map[string]*DomainData),
		RecipUser:    make(map[string]*DomainData),
		SendgDom:     make(map[string]*DomainData),
		RecipDom:     make(map[string]*DomainData),
		MsgsPerDay:   make(map[string][5]int),
		MsgSizes:     make(map[string]int),
		RcvdMsg:      make(map[string]string),
		MsgDfrdFlg:   make(map[string]int),
		NoMsgSize:    make(map[string]string),
		MsgDetail:    make(map[string][]string),
		Deferred:     make(map[string]map[string]int),
		Bounced:      make(map[string]map[string]int),
		Rejects:      make(map[string]map[string]map[string]int),
		Warns:        make(map[string]map[string]map[string]int),
		Holds:        make(map[string]map[string]map[string]int),
		Discards:     make(map[string]map[string]map[string]int),
		SmtpMsgs:     make(map[string]map[string]int),
		Warnings:     make(map[string]map[string]int),
		Fatals:       make(map[string]map[string]int),
		Panics:       make(map[string]map[string]int),
		MasterMsgs:   make(map[string]int),
		SmtpdPerDay:  make(map[string]*SmtpdDayData),
		SmtpdPerDom:  make(map[string]*SmtpdDomData),
		ConnTime:     make(map[string]*ConnTimeData),
		Requeue:      make(map[string]string),
	}
}

// EnsureRecipDom ensures the domain entry exists and returns it.
func (s *Stats) EnsureRecipDom(domain string) *DomainData {
	d, ok := s.RecipDom[domain]
	if !ok {
		d = &DomainData{}
		s.RecipDom[domain] = d
	}
	return d
}

// EnsureSendgDom ensures the sending domain entry exists and returns it.
func (s *Stats) EnsureSendgDom(domain string) *DomainData {
	d, ok := s.SendgDom[domain]
	if !ok {
		d = &DomainData{}
		s.SendgDom[domain] = d
	}
	return d
}

// EnsureSendgUser ensures the sending user entry exists and returns it.
func (s *Stats) EnsureSendgUser(user string) *DomainData {
	d, ok := s.SendgUser[user]
	if !ok {
		d = &DomainData{}
		s.SendgUser[user] = d
	}
	return d
}

// EnsureRecipUser ensures the recipient user entry exists and returns it.
func (s *Stats) EnsureRecipUser(user string) *DomainData {
	d, ok := s.RecipUser[user]
	if !ok {
		d = &DomainData{}
		s.RecipUser[user] = d
	}
	return d
}

// IncrRejects increments the triple-nested reject hash.
func (s *Stats) IncrRejects(rejects map[string]map[string]map[string]int, typ, reason, data string) {
	if _, ok := rejects[typ]; !ok {
		rejects[typ] = make(map[string]map[string]int)
	}
	if _, ok := rejects[typ][reason]; !ok {
		rejects[typ][reason] = make(map[string]int)
	}
	rejects[typ][reason][data]++
}

// IncrNested2 increments a double-nested hash.
func IncrNested2(hash map[string]map[string]int, key1, key2 string) {
	if _, ok := hash[key1]; !ok {
		hash[key1] = make(map[string]int)
	}
	hash[key1][key2]++
}

// UpdateMsgsPerDay safely updates per-day stats.
func (s *Stats) UpdateMsgsPerDay(dateStr string, index int) {
	d := s.MsgsPerDay[dateStr]
	d[index]++
	s.MsgsPerDay[dateStr] = d
}

// ZeroFillDay ensures a day entry exists with zero values.
func (s *Stats) ZeroFillDay(dateStr string) {
	if _, ok := s.MsgsPerDay[dateStr]; !ok {
		s.MsgsPerDay[dateStr] = [5]int{0, 0, 0, 0, 0}
	}
}
