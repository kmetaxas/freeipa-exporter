package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
)

// ldapConn abstracts the ldap.Conn methods we need for testability.
type ldapConn interface {
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// dialer is the function signature used to create an LDAP connection.
type dialer func(url string, opts ...ldap.DialOpt) (ldapConn, error)

// defaultDialer wraps ldap.DialURL to satisfy the dialer signature.
func defaultDialer(url string, opts ...ldap.DialOpt) (ldapConn, error) {
	return ldap.DialURL(url, opts...)
}

type LdapCollector struct {
	ldapServer     string
	ldapBaseDN     string
	ldapSearchDesc *prometheus.Desc
	hostname       string
	dial           dialer

	// cn=monitor metrics
	bytesSentDesc          *prometheus.Desc
	connectionDesc         *prometheus.Desc
	currentConnectionsDesc *prometheus.Desc
	dTableSizeDesc         *prometheus.Desc
	entriesSentDesc        *prometheus.Desc
	nbackEndsDesc          *prometheus.Desc
	opsInitiatedDesc       *prometheus.Desc
	readWaitersDesc        *prometheus.Desc
	startTimeDesc          *prometheus.Desc
	threadsDesc            *prometheus.Desc
	totalConnectionsDesc   *prometheus.Desc
	versionDesc            *prometheus.Desc
}

func NewLdapCollector(config LdapConfig) (*LdapCollector, error) {
	collector := LdapCollector{
		ldapServer: config.LdapUrl,
		ldapBaseDN: Value_or_default(config.BaseDN, ""),
		dial:       defaultDialer,
		ldapSearchDesc: prometheus.NewDesc(
			"freeipa_ldap_base_search_success",
			"1 if LDAP base search succeeded, 0 otherwise.",
			[]string{"server"},
			nil,
		),
		bytesSentDesc: prometheus.NewDesc(
			"freeipa_ldap_bytes_sent",
			"Number of bytes sent by the directory server since startup.",
			[]string{"server"},
			nil,
		),
		connectionDesc: prometheus.NewDesc(
			"freeipa_ldap_connections",
			"Number of connections currently in the connection table.",
			[]string{"server"},
			nil,
		),
		currentConnectionsDesc: prometheus.NewDesc(
			"freeipa_ldap_current_connections",
			"Number of currently open and active connections.",
			[]string{"server"},
			nil,
		),
		dTableSizeDesc: prometheus.NewDesc(
			"freeipa_ldap_dtable_size",
			"Size of the file descriptor table.",
			[]string{"server"},
			nil,
		),
		entriesSentDesc: prometheus.NewDesc(
			"freeipa_ldap_entries_sent",
			"Number of entries sent by the directory server since startup.",
			[]string{"server"},
			nil,
		),
		nbackEndsDesc: prometheus.NewDesc(
			"freeipa_ldap_nbackends",
			"Number of backend databases.",
			[]string{"server"},
			nil,
		),
		opsInitiatedDesc: prometheus.NewDesc(
			"freeipa_ldap_ops_initiated",
			"Number of operations initiated since startup.",
			[]string{"server"},
			nil,
		),
		readWaitersDesc: prometheus.NewDesc(
			"freeipa_ldap_read_waiters",
			"Number of threads waiting to read data from clients.",
			[]string{"server"},
			nil,
		),
		startTimeDesc: prometheus.NewDesc(
			"freeipa_ldap_start_time",
			"Unix timestamp when the directory server started.",
			[]string{"server"},
			nil,
		),
		threadsDesc: prometheus.NewDesc(
			"freeipa_ldap_threads",
			"Number of worker threads.",
			[]string{"server"},
			nil,
		),
		totalConnectionsDesc: prometheus.NewDesc(
			"freeipa_ldap_total_connections",
			"Total number of connections since the server started.",
			[]string{"server"},
			nil,
		),
		versionDesc: prometheus.NewDesc(
			"freeipa_ldap_version_info",
			"Directory server version info.",
			[]string{"server", "version"},
			nil,
		),
	}
	collector.getHostname()
	return &collector, nil
}

func (c *LdapCollector) getHostname() {
	c.hostname, _ = os.Hostname()
}

func (c *LdapCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.ldapSearchDesc
	ch <- c.bytesSentDesc
	ch <- c.connectionDesc
	ch <- c.currentConnectionsDesc
	ch <- c.dTableSizeDesc
	ch <- c.entriesSentDesc
	ch <- c.nbackEndsDesc
	ch <- c.opsInitiatedDesc
	ch <- c.readWaitersDesc
	ch <- c.startTimeDesc
	ch <- c.threadsDesc
	ch <- c.totalConnectionsDesc
	ch <- c.versionDesc
}

func (c *LdapCollector) Collect(ch chan<- prometheus.Metric) {
	ldapOK := c.checkLDAP()
	var ldapValue float64
	if ldapOK {
		ldapValue = 1
	}
	ch <- prometheus.MustNewConstMetric(c.ldapSearchDesc, prometheus.GaugeValue, ldapValue, c.hostname)

	// Query cn=monitor regardless of base search result; if it fails we simply skip the metrics.
	monitorAttrs, err := c.queryMonitor()
	if err != nil {
		log.Printf("ldap: cn=monitor query failed: %v", err)
		return
	}

	emit := func(desc *prometheus.Desc, value float64, labelValues ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
	}

	if v, ok := monitorAttrs["bytessent"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.bytesSentDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["connection"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.connectionDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["currentconnections"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.currentConnectionsDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["dtablesize"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.dTableSizeDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["entriessent"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.entriesSentDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["nbackends"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.nbackEndsDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["opsinitiated"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.opsInitiatedDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["readwaiters"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.readWaitersDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["starttime"]; ok {
		if t, err := time.Parse("20060102150405Z", v); err == nil {
			emit(c.startTimeDesc, float64(t.Unix()), c.hostname)
		}
	}
	if v, ok := monitorAttrs["threads"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.threadsDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["totalconnections"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			emit(c.totalConnectionsDesc, f, c.hostname)
		}
	}
	if v, ok := monitorAttrs["version"]; ok {
		ch <- prometheus.MustNewConstMetric(c.versionDesc, prometheus.GaugeValue, 1, c.hostname, v)
	}
}

func (c *LdapCollector) checkLDAP() bool {
	// Dial LDAP with a timeout.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := c.dial(c.ldapServer, ldap.DialWithDialer(dialer))
	if err != nil {
		log.Printf("ldap: failed to dial %s: %v", c.ldapServer, err)
		return false
	}
	defer conn.Close()

	// Base-object search.
	sr, err := conn.Search(ldap.NewSearchRequest(
		c.ldapBaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{"namingContexts"},
		nil,
	))
	if err != nil {
		log.Printf("ldap: base search failed: %v", err)
		return false
	}
	if len(sr.Entries) == 0 {
		log.Printf("ldap: base search returned no entries")
		return false
	}
	return true
}

func (c *LdapCollector) queryMonitor() (map[string]string, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := c.dial(c.ldapServer, ldap.DialWithDialer(dialer))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sr, err := conn.Search(ldap.NewSearchRequest(
		"cn=monitor",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{
			"bytessent",
			"connection",
			"currentconnections",
			"dtablesize",
			"entriessent",
			"nbackends",
			"opsinitiated",
			"readwaiters",
			"starttime",
			"threads",
			"totalconnections",
			"version",
		},
		nil,
	))
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, nil
	}

	entry := sr.Entries[0]
	result := make(map[string]string)
	for _, attr := range entry.Attributes {
		if len(attr.Values) > 0 {
			result[attr.Name] = attr.Values[0]
		}
	}
	return result, nil
}
