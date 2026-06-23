package main

import (
	"log"
	"maps"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jdrews/go-tailer/fswatcher"
	"github.com/jdrews/go-tailer/glob"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const defaultKrb5KDCLogPath = "/var/log/krb5kdc.log"

type krb5TGSLabel struct {
	principal string
	service   string
	host      string
}

type krb5LogState struct {
	ticketIssueErrors float64
	tgtIssued         map[string]float64
	tgsIssued         map[krb5TGSLabel]float64
	lockedOut         map[string]float64
}

type Krb5LogCollector struct {
	logPath      string
	pollInterval time.Duration
	hostname     string
	stopCh       chan struct{}
	doneCh       chan struct{}

	mu    sync.RWMutex
	state krb5LogState

	ticketIssueErrorsDesc *prometheus.Desc
	tgtIssuedDesc         *prometheus.Desc
	tgsIssuedDesc         *prometheus.Desc
	lockedOutDesc         *prometheus.Desc
}

func NewKrb5LogCollector(config KerberosConfig) (*Krb5LogCollector, error) {
	collector := newKrb5LogCollector(config, 5*time.Second)
	collector.getHostname()
	go collector.run()
	return collector, nil
}

func newKrb5LogCollector(config KerberosConfig, pollInterval time.Duration) *Krb5LogCollector {
	return &Krb5LogCollector{
		logPath:      Value_or_default(config.KdcLogPath, defaultKrb5KDCLogPath),
		pollInterval: pollInterval,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		state: krb5LogState{
			tgtIssued: make(map[string]float64),
			tgsIssued: make(map[krb5TGSLabel]float64),
			lockedOut: make(map[string]float64),
		},
		ticketIssueErrorsDesc: prometheus.NewDesc(
			"freeipa_krb5_ticket_issue_errors_total",
			"Total number of Kerberos ticket issue errors observed in krb5kdc.log.",
			[]string{"server"},
			nil,
		),
		tgtIssuedDesc: prometheus.NewDesc(
			"freeipa_krb5_tgt_tickets_issued_total",
			"Total number of Kerberos TGT tickets issued, labelled by principal.",
			[]string{"server", "principal"},
			nil,
		),
		tgsIssuedDesc: prometheus.NewDesc(
			"freeipa_krb5_tgs_tickets_issued_total",
			"Total number of Kerberos TGS tickets issued, labelled by principal, service, and host.",
			[]string{"server", "principal", "service", "host"},
			nil,
		),
		lockedOutDesc: prometheus.NewDesc(
			"freeipa_krb5_locked_out_accounts_total",
			"Total number of Kerberos LOCKED_OUT events observed, labelled by principal.",
			[]string{"server", "principal"},
			nil,
		),
	}
}

func (c *Krb5LogCollector) getHostname() {
	c.hostname, _ = os.Hostname()
}

func (c *Krb5LogCollector) Stop() {
	select {
	case <-c.doneCh:
		return
	default:
	}
	close(c.stopCh)
	<-c.doneCh
}

func (c *Krb5LogCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.ticketIssueErrorsDesc
	ch <- c.tgtIssuedDesc
	ch <- c.tgsIssuedDesc
	ch <- c.lockedOutDesc
}

func (c *Krb5LogCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	snapshot := krb5LogState{
		ticketIssueErrors: c.state.ticketIssueErrors,
		tgtIssued:         make(map[string]float64, len(c.state.tgtIssued)),
		tgsIssued:         make(map[krb5TGSLabel]float64, len(c.state.tgsIssued)),
		lockedOut:         make(map[string]float64, len(c.state.lockedOut)),
	}
	maps.Copy(snapshot.tgtIssued, c.state.tgtIssued)
	maps.Copy(snapshot.tgsIssued, c.state.tgsIssued)
	maps.Copy(snapshot.lockedOut, c.state.lockedOut)
	c.mu.RUnlock()

	ch <- prometheus.MustNewConstMetric(c.ticketIssueErrorsDesc, prometheus.CounterValue, snapshot.ticketIssueErrors, c.hostname)
	for principal, value := range snapshot.tgtIssued {
		ch <- prometheus.MustNewConstMetric(c.tgtIssuedDesc, prometheus.CounterValue, value, c.hostname, principal)
	}
	for labels, value := range snapshot.tgsIssued {
		ch <- prometheus.MustNewConstMetric(c.tgsIssuedDesc, prometheus.CounterValue, value, c.hostname, labels.principal, labels.service, labels.host)
	}
	for principal, value := range snapshot.lockedOut {
		ch <- prometheus.MustNewConstMetric(c.lockedOutDesc, prometheus.CounterValue, value, c.hostname, principal)
	}
}

func (c *Krb5LogCollector) run() {
	defer close(c.doneCh)

	parsedGlob, err := glob.Parse(c.logPath)
	if err != nil {
		log.Printf("krb5 log: failed to parse glob %s: %v", c.logPath, err)
		return
	}

	logger := logrus.New()
	tailer, err := fswatcher.RunPollingFileTailer([]glob.Glob{parsedGlob}, true, false, c.pollInterval, logger)
	if err != nil {
		log.Printf("krb5 log: failed to start tailer for %s: %v", c.logPath, err)
		return
	}
	defer tailer.Close()

	for {
		select {
		case line, ok := <-tailer.Lines():
			if !ok {
				return
			}
			c.parseLine(line.Line)
		case <-c.stopCh:
			return
		}
	}
}

func (c *Krb5LogCollector) parseLine(line string) {
	principal, ticket := parseKrb5PrincipalAndTicket(line)
	if principal == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if strings.Contains(line, "LOCKED_OUT") {
		c.state.lockedOut[principal]++
		c.state.ticketIssueErrors++
		return
	}

	if !strings.Contains(line, "ISSUE:") && !strings.Contains(line, "NEEDED_PREAUTH") {
		if strings.Contains(line, "AS_REQ") || strings.Contains(line, "TGS_REQ") {
			c.state.ticketIssueErrors++
		}
		return
	}

	if strings.HasPrefix(ticket, "krbtgt/") {
		c.state.tgtIssued[principal]++
		return
	}

	service, host := splitKrb5Service(ticket)
	c.state.tgsIssued[krb5TGSLabel{principal: principal, service: service, host: host}]++
}

func parseKrb5PrincipalAndTicket(line string) (string, string) {
	principal, after, ok := strings.Cut(line, " for ")
	if !ok {
		return "", ""
	}
	fields := strings.Fields(principal)
	if len(fields) == 0 {
		return "", ""
	}
	principal = strings.TrimRight(fields[len(fields)-1], ",")

	ticketFields := strings.Fields(after)
	if len(ticketFields) == 0 {
		return principal, ""
	}
	ticket := strings.TrimRight(ticketFields[0], ",")
	return principal, ticket
}

func splitKrb5Service(ticket string) (string, string) {
	withoutRealm, _, _ := strings.Cut(ticket, "@")
	service, host, ok := strings.Cut(withoutRealm, "/")
	if !ok {
		return withoutRealm, ""
	}
	return service, host
}
