import (
	"fmt"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
)

type LdapCollector struct {
	ldapServer     string
	ldapBaseDN     string
	ldapSearchDesc *prometheus.Desc
}

func newLdapCollector(config LdapConfig) (*LdapConfig, error) {
	collector := LdapCollector{
		ldapServer:     config.LdapUrl,
		ldabBaseDN:     value_or_default(config.BaseDN, ""),
		ldapSearchDesc: value_or_default(config.LdapQuery, "namingContexts supportedLDAPVersion"),
		ldapSearchDesc: prometheus.NewDesc(
			"freeipa_ldap_base_search_success",
			"1 if LDAP base search succeeded, 0 otherwise.",
			nil, nil,
		),
	}
	return &collector, nil
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
	ch <- prometheus.MustNewConstMetric(c.ldapSearchDesc, prometheus.GaugeValue, ldapValue)
}

// checkLDAP performs a base-object LDAP search against FreeIPA using a
// GSSAPI SASL bind (Kerberos keytab).  It returns true if the search
// succeeds and returns at least one entry.
func (c *LdapCollector) checkLDAP() bool {
	// Dial LDAP with a timeout.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := ldap.DialURL(c.ldapServer, ldap.DialWithDialer(dialer))
	if err != nil {
		log.Printf("ldap: failed to dial %s: %v", c.ldapServer, err)
		return false
	}
	defer conn.Close()

	// Derive the SPN from the LDAP server URL: ldap/<hostname>
	u, err := url.Parse(c.ldapServer)
	if err != nil {
		log.Printf("ldap: failed to parse LDAP URL %s: %v", c.ldapServer, err)
		return false
	}
	spn := fmt.Sprintf("ldap/%s", u.Hostname())

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
