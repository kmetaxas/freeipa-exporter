# FreeIPA Exporter

A lightweight [Prometheus](https://prometheus.io/) exporter for monitoring the health of core [FreeIPA](https://www.freeipa.org/) services.

> **Status:** Early stage. Currently exposes a small set of health-check metrics with plans to expand coverage over time.

## What it checks

| Collector    | Metric                               | Description                                               |
| ------------ | ------------------------------------ | --------------------------------------------------------- |
| **LDAP**     | `freeipa_ldap_base_search_success`   | `1` if a base-object LDAP search succeeds, `0` otherwise. |
| **LDAP**     | `freeipa_ldap_bytes_sent`            | Number of bytes sent by the directory server since startup. |
| **LDAP**     | `freeipa_ldap_connections`           | Number of connections currently in the connection table.  |
| **LDAP**     | `freeipa_ldap_current_connections`   | Number of currently open and active connections.          |
| **LDAP**     | `freeipa_ldap_dtable_size`           | Size of the file descriptor table.                        |
| **LDAP**     | `freeipa_ldap_entries_sent`          | Number of entries sent by the directory server since startup. |
| **LDAP**     | `freeipa_ldap_nbackends`             | Number of backend databases.                              |
| **LDAP**     | `freeipa_ldap_ops_initiated`         | Number of operations initiated since startup.             |
| **LDAP**     | `freeipa_ldap_read_waiters`          | Number of threads waiting to read data from clients.      |
| **LDAP**     | `freeipa_ldap_start_time`            | Unix timestamp when the directory server started.         |
| **LDAP**     | `freeipa_ldap_threads`               | Number of worker threads.                                 |
| **LDAP**     | `freeipa_ldap_total_connections`     | Total number of connections since the server started.     |
| **LDAP**     | `freeipa_ldap_version_info`            | Directory server version info.                            |
| **Kerberos** | `freeipa_krb5_tgt_issue_success`     | `1` if a TGT is issued successfully, `0` otherwise.       |
| **Kerberos** | `freeipa_krb5_ticket_issue_errors_total` | Ticket issue errors observed in `krb5kdc.log`.         |
| **Kerberos** | `freeipa_krb5_tgt_tickets_issued_total` | TGT tickets issued, labelled by principal.             |
| **Kerberos** | `freeipa_krb5_tgs_tickets_issued_total` | TGS tickets issued, labelled by principal, service, and host. |
| **Kerberos** | `freeipa_krb5_locked_out_accounts_total` | `LOCKED_OUT` events, labelled by principal.            |

All metrics are labelled by `server` (hostname) so you can aggregate across a fleet.

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
     # kdcLogPath: "/var/log/krb5kdc.log" # optional, defaults to /var/log/krb5kdc.log
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
