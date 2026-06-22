package main

import (
	"log"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/prometheus/client_golang/prometheus"
)

type Krb5Collector struct {
	keytabPath   string
	principal    string
	realm        string
	krb5ConfPath string
	krb5TGTDesc  *prometheus.Desc
}

func NewKrb5Collector(config KerberosConfig) (*Krb5Collector, error) {
	collector := Krb5Collector{
		keytabPath:   config.KeytabPath,
		principal:    config.Principal,
		krb5ConfPath: Value_or_default(config.Krb5ConfPath, "/etc/krb5.conf"),
		realm:        config.Realm,
		krb5TGTDesc: prometheus.NewDesc(
			"freeipa_krb5_tgt_issued",
			"How many tickets have been issued.",
			nil, nil,
		),
	}

	return &collector, nil
}

func (c *Krb5Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.krb5TGTDesc
}

func (c *Krb5Collector) Collect(ch chan<- prometheus.Metric) {
	// 1. Kerberos TGT check
	tgtOK := c.checkTGT()
	var tgtValue float64
	if tgtOK {
		tgtValue = 1
	}
	ch <- prometheus.MustNewConstMetric(c.krb5TGTDesc, prometheus.GaugeValue, tgtValue)
}

// checkTGT attempts to acquire a Kerberos TGT using the provided keytab.
// It returns true if a TGT is successfully obtained.
func (c *Krb5Collector) checkTGT() bool {
	cfg, err := config.Load(c.krb5ConfPath)
	if err != nil {
		log.Printf("krb5: failed to load krb5.conf (%s): %v", c.krb5ConfPath, err)
		return false
	}

	kt, err := keytab.Load(c.keytabPath)
	if err != nil {
		log.Printf("krb5: failed to load keytab (%s): %v", c.keytabPath, err)
		return false
	}

	cl := client.NewWithKeytab(c.principal, c.realm, kt, cfg)
	if err := cl.Login(); err != nil {
		log.Printf("krb5: failed to login / acquire TGT for %s: %v", c.principal, err)
		return false
	}
	return true
}
