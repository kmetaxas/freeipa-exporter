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
	config, err := NewConfig()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(-1)
	}
	reg := prometheus.NewRegistry()

	ldapCollector, err := NewLdapCollector(config.Ldap)
	if err != nil {
		fmt.Printf("Error creating ldap collector: %s\n", err)
		os.Exit(-1)
	}
	krb5Collector, err := NewKrb5Collector(config.Kerberos)
	if err != nil {
		fmt.Printf("Error creating Kerberos collector: %s\n", err)
		os.Exit(-1)
	}
	krb5LogCollector, err := NewKrb5LogCollector(config.Kerberos)
	if err != nil {
		fmt.Printf("Error creating Kerberos log collector: %s\n", err)
		os.Exit(-1)
	}

	if err := reg.Register(ldapCollector); err != nil {
		log.Fatalf("failed to register ldap collector: %v", err)
	}
	if err := reg.Register(krb5Collector); err != nil {
		log.Fatalf("failed to register krb5 collector: %v", err)
	}
	if err := reg.Register(krb5LogCollector); err != nil {
		log.Fatalf("failed to register krb5 log collector: %v", err)
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

	fmt.Printf("Starting exporter. Listening on %s:%s\n", config.Exporter.ListenAddr, config.Exporter.ListenPort)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%s", config.Exporter.ListenAddr, config.Exporter.ListenPort), mux); err != nil {
		log.Fatalf("failed to start HTTP server: %v", err)
	}
}
