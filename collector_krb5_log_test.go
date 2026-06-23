package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newTestKrb5LogCollector(path string) *Krb5LogCollector {
	c := newKrb5LogCollector(KerberosConfig{KdcLogPath: path}, time.Hour)
	c.hostname = "testhost"
	return c
}

func TestKrb5LogCollectorParseLine(t *testing.T) {
	c := newTestKrb5LogCollector("")

	lines := []string{
		`Nov 20 12:00:01 ipa.example.com krb5kdc[123](info): AS_REQ (8 etypes {aes256-cts}) 192.0.2.10: ISSUE: authtime 1700481601, etypes {rep=aes256-cts tkt=aes256-cts ses=aes256-cts}, user1@EXAMPLE.COM for krbtgt/EXAMPLE.COM@EXAMPLE.COM`,
		`Nov 20 12:00:02 ipa.example.com krb5kdc[123](info): TGS_REQ (8 etypes {aes256-cts}) 192.0.2.10: ISSUE: authtime 1700481601, etypes {rep=aes256-cts tkt=aes256-cts ses=aes256-cts}, user1@EXAMPLE.COM for HTTP/app.example.com@EXAMPLE.COM`,
		`Nov 20 12:00:03 ipa.example.com krb5kdc[123](info): AS_REQ (8 etypes {aes256-cts}) 192.0.2.11: LOCKED_OUT: user2@EXAMPLE.COM for krbtgt/EXAMPLE.COM@EXAMPLE.COM, Account locked out`,
		`Nov 20 12:00:04 ipa.example.com krb5kdc[123](info): TGS_REQ (8 etypes {aes256-cts}) 192.0.2.12: UNKNOWN_SERVER: user3@EXAMPLE.COM for ldap/missing.example.com@EXAMPLE.COM, Server not found in Kerberos database`,
	}

	for _, line := range lines {
		c.parseLine(line)
	}

	if got := c.state.tgtIssued["user1@EXAMPLE.COM"]; got != 1 {
		t.Fatalf("expected 1 TGT for user1, got %v", got)
	}
	if got := c.state.tgsIssued[krb5TGSLabel{principal: "user1@EXAMPLE.COM", service: "HTTP", host: "app.example.com"}]; got != 1 {
		t.Fatalf("expected 1 TGS for HTTP/app.example.com, got %v", got)
	}
	if got := c.state.lockedOut["user2@EXAMPLE.COM"]; got != 1 {
		t.Fatalf("expected 1 lockout for user2, got %v", got)
	}
	if got := c.state.ticketIssueErrors; got != 2 {
		t.Fatalf("expected 2 ticket issue errors, got %v", got)
	}
}

func TestKrb5LogCollectorCollectCachedMetrics(t *testing.T) {
	c := newTestKrb5LogCollector("")
	c.parseLine(`Nov 20 12:00:01 ipa.example.com krb5kdc[123](info): AS_REQ (8 etypes {aes256-cts}) 192.0.2.10: ISSUE: authtime 1700481601, etypes {rep=aes256-cts tkt=aes256-cts ses=aes256-cts}, user1@EXAMPLE.COM for krbtgt/EXAMPLE.COM@EXAMPLE.COM`)
	c.parseLine(`Nov 20 12:00:02 ipa.example.com krb5kdc[123](info): TGS_REQ (8 etypes {aes256-cts}) 192.0.2.10: ISSUE: authtime 1700481601, etypes {rep=aes256-cts tkt=aes256-cts ses=aes256-cts}, user1@EXAMPLE.COM for HTTP/app.example.com@EXAMPLE.COM`)
	c.parseLine(`Nov 20 12:00:03 ipa.example.com krb5kdc[123](info): AS_REQ (8 etypes {aes256-cts}) 192.0.2.11: LOCKED_OUT: user2@EXAMPLE.COM for krbtgt/EXAMPLE.COM@EXAMPLE.COM, Account locked out`)

	expected := `
		# HELP freeipa_krb5_locked_out_accounts_total Total number of Kerberos LOCKED_OUT events observed, labelled by principal.
		# TYPE freeipa_krb5_locked_out_accounts_total counter
		freeipa_krb5_locked_out_accounts_total{principal="user2@EXAMPLE.COM",server="testhost"} 1
		# HELP freeipa_krb5_tgs_tickets_issued_total Total number of Kerberos TGS tickets issued, labelled by principal, service, and host.
		# TYPE freeipa_krb5_tgs_tickets_issued_total counter
		freeipa_krb5_tgs_tickets_issued_total{host="app.example.com",principal="user1@EXAMPLE.COM",server="testhost",service="HTTP"} 1
		# HELP freeipa_krb5_tgt_tickets_issued_total Total number of Kerberos TGT tickets issued, labelled by principal.
		# TYPE freeipa_krb5_tgt_tickets_issued_total counter
		freeipa_krb5_tgt_tickets_issued_total{principal="user1@EXAMPLE.COM",server="testhost"} 1
		# HELP freeipa_krb5_ticket_issue_errors_total Total number of Kerberos ticket issue errors observed in krb5kdc.log.
		# TYPE freeipa_krb5_ticket_issue_errors_total counter
		freeipa_krb5_ticket_issue_errors_total{server="testhost"} 1
	`

	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("metric mismatch: %v", err)
	}
}

func TestKrb5LogCollectorTailsFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "krb5kdc.log")

	line := "Nov 20 12:00:01 ipa.example.com krb5kdc[123](info): AS_REQ (8 etypes {aes256-cts}) 192.0.2.10: ISSUE: authtime 1700481601, etypes {rep=aes256-cts tkt=aes256-cts ses=aes256-cts}, user1@EXAMPLE.COM for krbtgt/EXAMPLE.COM@EXAMPLE.COM\n"
	if err := os.WriteFile(logPath, []byte(line), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	c := newTestKrb5LogCollector(logPath)
	c.pollInterval = 50 * time.Millisecond

	go c.run()

	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.RLock()
		got := c.state.tgtIssued["user1@EXAMPLE.COM"]
		c.mu.RUnlock()
		if got == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 1 TGT after initial read, got %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}
	f.Close()

	deadline = time.Now().Add(2 * time.Second)
	for {
		c.mu.RLock()
		got := c.state.tgtIssued["user1@EXAMPLE.COM"]
		c.mu.RUnlock()
		if got == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 2 TGTs after append, got %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}

	c.Stop()
}

func TestKrb5LogCollectorDescribe(t *testing.T) {
	c := newTestKrb5LogCollector("")
	ch := make(chan *prometheus.Desc, 4)
	c.Describe(ch)
	close(ch)

	if len(ch) != 4 {
		t.Fatalf("expected 4 descriptors, got %d", len(ch))
	}
}
