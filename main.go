package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// listenAddr := flag.String("listen-address", ":9101", "HTTP listen address for Prometheus metrics")
	flag.Parse()

	// Parse config
	config, err := newConfig()
	if err != nil {
		fmt.Printf("Error: %s", err)
		os.Exit(-1)
	}
	fmt.Printf("Main config: %+s", config)
	reg := prometheus.NewRegistry()

	ldapCollector, err := newLdapCollector(config.Ldap)
	if err != nil {
		fmt.Printf("Error creating ldap collector: %s", err)
		os.Exit(-1)
	}
	krb5Collector, err := newKrb5Collector(config.Kerberos)
	if err != nil {
		fmt.Printf("Error creating Kerberos collector: %s", err)
		os.Exit(-1)
	}

	if err := reg.Register(ldapCollector); err != nil {
		log.Fatalf("failed to register ldap collector: %v", err)
	}
	if err := reg.Register(krb5Collector); err != nil {
		log.Fatalf("failed to register krb5 collector: %v", err)
	}

	// Optional: expose build info metric.
	versionGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "freeipa_exporter_build_info",
		Help: "A constant with value 1 labelled by version and Go version.",
		ConstLabels: prometheus.Labels{
			"version":   "0.1.0",
			"goversion": os.Getenv("GOVERSION"),
		},
	})
	versionGauge.Set(1)
	reg.MustRegister(versionGauge)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
<head><title>FreeIPA Exporter</title></head>
<body>
<h1>FreeIPA Exporter</h1>
<p><a href="/metrics">Metrics</a></p>
<p><a href="/healthz">Health</a></p>
</body>
</html>
`))
	})

	log.Printf("freeipa-exporter starting on %s", *listenAddr)
	log.Printf("  principal: %s", *principal)
	log.Printf("  keytab:    %s", *keytabPath)
	log.Printf("  ldap:      %s  baseDN: %s", *ldapServer, *ldapBaseDN)

	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		log.Fatalf("failed to start HTTP server: %v", err)
	}
}
