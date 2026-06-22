# FreeIPA Exporter

A lightweight [Prometheus](https://prometheus.io/) exporter for monitoring the health of core [FreeIPA](https://www.freeipa.org/) services.

> **Status:** Early stage. Currently exposes a small set of health-check metrics with plans to expand coverage over time.

## What it checks

| Collector    | Metric                             | Description                                               |
| ------------ | ---------------------------------- | --------------------------------------------------------- |
| **LDAP**     | `freeipa_ldap_base_search_success` | `1` if a base-object LDAP search succeeds, `0` otherwise. |
| **Kerberos** | `freeipa_krb5_tgt_issue_success`   | `1` if a TGT is issued successfully, `0` otherwise.       |

Both metrics are labelled by `server` (hostname) so you can aggregate across a fleet.

## Quick start

1. **Configure** `freeipa_exporter.yaml`:

   ```yaml
   ldap:
     ldapUrl: "ldaps://ipa.example.com:636"
     baseDN: "dc=example,dc=com"
     caPath: "/etc/ipa/ca.crt" # optional
   kerberos:
     username: "admin"
     realm: "EXAMPLE.COM"
     password: "yourpass"
     # either pass or keytab , but not both
     keytabPath: "/etc/freeipa-exporter/exporter.keytab"
     # krb5confPath: "/etc/krb5.conf"   # optional, defaults to /etc/krb5.conf
   exporter:
     #listenAddr: "0.0.0.0" # optional, defaults to all interfaces.
     port: "9195"
   ```

   > Authentication supports either a **keytab** or a **password**, but not both.

2. **Build & run:**

   ```bash
   make build
   ./freeipa-exporter
   ```

3. **Scrape metrics:**

   ```bash
   curl http://localhost:9195/metrics
   ```

4. **Health endpoint:**

   ```bash
   curl http://localhost:9195/healthz
   ```

## Requirements

- Go 1.26+
- Network access to the FreeIPA LDAP and Kerberos services

```

## License

GPL 3
```
