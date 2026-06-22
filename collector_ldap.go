package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
)

type LdapCollector struct {
	ldapServer     string
	ldapBaseDN     string
	ldapSearchDesc *prometheus.Desc
	hostname       string
}

func NewLdapCollector(config LdapConfig) (*LdapCollector, error) {
	collector := LdapCollector{
		ldapServer: config.LdapUrl,
		ldapBaseDN: Value_or_default(config.BaseDN, ""),
		ldapSearchDesc: prometheus.NewDesc(
			"freeipa_ldap_base_search_success",
			"1 if LDAP base search succeeded, 0 otherwise.",
			[]string{"server"},
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
}

func (c *LdapCollector) Collect(ch chan<- prometheus.Metric) {
	ldapOK := c.checkLDAP()
	var ldapValue float64
	if ldapOK {
		ldapValue = 1
	}
	ch <- prometheus.MustNewConstMetric(c.ldapSearchDesc, prometheus.GaugeValue, ldapValue, c.hostname)
}

func (c *LdapCollector) checkLDAP() bool {
	// Dial LDAP with a timeout.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := ldap.DialURL(c.ldapServer, ldap.DialWithDialer(dialer))
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
