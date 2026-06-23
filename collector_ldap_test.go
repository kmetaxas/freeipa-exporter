package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// mockLDAPConn is a test double for ldapConn.
type mockLDAPConn struct {
	searchFunc func(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	closeCalls int
}

func (m *mockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if m.searchFunc != nil {
		return m.searchFunc(req)
	}
	return nil, errors.New("no searchFunc configured")
}

func (m *mockLDAPConn) Close() error {
	m.closeCalls++
	return nil
}

// fakeDialer returns a dialer that always yields the provided mockLDAPConn.
func fakeDialer(conn ldapConn) dialer {
	return func(url string, opts ...ldap.DialOpt) (ldapConn, error) {
		return conn, nil
	}
}

// failingDialer returns a dialer that always errors.
func failingDialer(err error) dialer {
	return func(url string, opts ...ldap.DialOpt) (ldapConn, error) {
		return nil, err
	}
}

func newTestCollector(t *testing.T) *LdapCollector {
	c, err := NewLdapCollector(LdapConfig{LdapUrl: "ldap://test:389", BaseDN: "dc=test,dc=com"})
	if err != nil {
		t.Fatalf("NewLdapCollector failed: %v", err)
	}
	c.hostname = "testhost"
	return c
}

func TestNewLdapCollector(t *testing.T) {
	c, err := NewLdapCollector(LdapConfig{LdapUrl: "ldap://test:389", BaseDN: "dc=test,dc=com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ldapServer != "ldap://test:389" {
		t.Errorf("expected ldapServer ldap://test:389, got %s", c.ldapServer)
	}
	if c.ldapBaseDN != "dc=test,dc=com" {
		t.Errorf("expected baseDN dc=test,dc=com, got %s", c.ldapBaseDN)
	}
	if c.dial == nil {
		t.Error("expected dial to be set")
	}
}

func TestLdapCollectorDescribe(t *testing.T) {
	c := newTestCollector(t)
	ch := make(chan *prometheus.Desc, 20)
	c.Describe(ch)
	close(ch)

	expected := []string{
		"freeipa_ldap_base_search_success",
		"freeipa_ldap_bytes_sent",
		"freeipa_ldap_connections",
		"freeipa_ldap_current_connections",
		"freeipa_ldap_dtable_size",
		"freeipa_ldap_entries_sent",
		"freeipa_ldap_nbackends",
		"freeipa_ldap_ops_initiated",
		"freeipa_ldap_read_waiters",
		"freeipa_ldap_start_time",
		"freeipa_ldap_threads",
		"freeipa_ldap_total_connections",
		"freeipa_ldap_version_info",
	}

	var count int
	for desc := range ch {
		count++
		found := false
		for _, name := range expected {
			if strings.Contains(desc.String(), name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected desc: %s", desc.String())
		}
	}
	if count != len(expected) {
		t.Errorf("expected %d descriptors, got %d", len(expected), count)
	}
}

func TestLdapCollectorCollectAllMetrics(t *testing.T) {
	c := newTestCollector(t)

	monitorEntry := &ldap.Entry{
		DN: "cn=monitor",
		Attributes: []*ldap.EntryAttribute{
			{Name: "bytessent", Values: []string{"1234"}},
			{Name: "connection", Values: []string{"42"}},
			{Name: "currentconnections", Values: []string{"10"}},
			{Name: "dtablesize", Values: []string{"4096"}},
			{Name: "entriessent", Values: []string{"500"}},
			{Name: "nbackends", Values: []string{"1"}},
			{Name: "opsinitiated", Values: []string{"1000"}},
			{Name: "readwaiters", Values: []string{"2"}},
			{Name: "starttime", Values: []string{"20220101120000Z"}},
			{Name: "threads", Values: []string{"24"}},
			{Name: "totalconnections", Values: []string{"200"}},
			{Name: "version", Values: []string{"389-Directory/2.0"}},
		},
	}

	baseEntry := &ldap.Entry{
		DN: "dc=test,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "namingContexts", Values: []string{"dc=test,dc=com"}},
		},
	}

	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if req.BaseDN == "cn=monitor" {
				return &ldap.SearchResult{Entries: []*ldap.Entry{monitorEntry}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{baseEntry}}, nil
		},
	}
	c.dial = fakeDialer(mock)

	expected := `
		# HELP freeipa_ldap_base_search_success 1 if LDAP base search succeeded, 0 otherwise.
		# TYPE freeipa_ldap_base_search_success gauge
		freeipa_ldap_base_search_success{server="testhost"} 1
		# HELP freeipa_ldap_bytes_sent Number of bytes sent by the directory server since startup.
		# TYPE freeipa_ldap_bytes_sent gauge
		freeipa_ldap_bytes_sent{server="testhost"} 1234
		# HELP freeipa_ldap_connections Number of connections currently in the connection table.
		# TYPE freeipa_ldap_connections gauge
		freeipa_ldap_connections{server="testhost"} 42
		# HELP freeipa_ldap_current_connections Number of currently open and active connections.
		# TYPE freeipa_ldap_current_connections gauge
		freeipa_ldap_current_connections{server="testhost"} 10
		# HELP freeipa_ldap_dtable_size Size of the file descriptor table.
		# TYPE freeipa_ldap_dtable_size gauge
		freeipa_ldap_dtable_size{server="testhost"} 4096
		# HELP freeipa_ldap_entries_sent Number of entries sent by the directory server since startup.
		# TYPE freeipa_ldap_entries_sent gauge
		freeipa_ldap_entries_sent{server="testhost"} 500
		# HELP freeipa_ldap_nbackends Number of backend databases.
		# TYPE freeipa_ldap_nbackends gauge
		freeipa_ldap_nbackends{server="testhost"} 1
		# HELP freeipa_ldap_ops_initiated Number of operations initiated since startup.
		# TYPE freeipa_ldap_ops_initiated gauge
		freeipa_ldap_ops_initiated{server="testhost"} 1000
		# HELP freeipa_ldap_read_waiters Number of threads waiting to read data from clients.
		# TYPE freeipa_ldap_read_waiters gauge
		freeipa_ldap_read_waiters{server="testhost"} 2
		# HELP freeipa_ldap_start_time Unix timestamp when the directory server started.
		# TYPE freeipa_ldap_start_time gauge
		freeipa_ldap_start_time{server="testhost"} 1.6410384e+09
		# HELP freeipa_ldap_threads Number of worker threads.
		# TYPE freeipa_ldap_threads gauge
		freeipa_ldap_threads{server="testhost"} 24
		# HELP freeipa_ldap_total_connections Total number of connections since the server started.
		# TYPE freeipa_ldap_total_connections gauge
		freeipa_ldap_total_connections{server="testhost"} 200
		# HELP freeipa_ldap_version_info Directory server version info.
		# TYPE freeipa_ldap_version_info gauge
		freeipa_ldap_version_info{server="testhost",version="389-Directory/2.0"} 1
	`

	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("metric mismatch: %v", err)
	}
	if mock.closeCalls != 2 {
		t.Errorf("expected 2 Close calls, got %d", mock.closeCalls)
	}
}

func TestLdapCollectorCollectBaseSearchFails(t *testing.T) {
	c := newTestCollector(t)
	c.dial = failingDialer(errors.New("connection refused"))

	expected := `
		# HELP freeipa_ldap_base_search_success 1 if LDAP base search succeeded, 0 otherwise.
		# TYPE freeipa_ldap_base_search_success gauge
		freeipa_ldap_base_search_success{server="testhost"} 0
	`

	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("metric mismatch: %v", err)
	}
}

func TestLdapCollectorCollectMonitorQueryFails(t *testing.T) {
	c := newTestCollector(t)

	baseEntry := &ldap.Entry{
		DN: "dc=test,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "namingContexts", Values: []string{"dc=test,dc=com"}},
		},
	}

	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if req.BaseDN == "cn=monitor" {
				return nil, errors.New("monitor search failed")
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{baseEntry}}, nil
		},
	}
	c.dial = fakeDialer(mock)

	expected := `
		# HELP freeipa_ldap_base_search_success 1 if LDAP base search succeeded, 0 otherwise.
		# TYPE freeipa_ldap_base_search_success gauge
		freeipa_ldap_base_search_success{server="testhost"} 1
	`

	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("metric mismatch: %v", err)
	}
}

func TestLdapCollectorCollectPartialMonitorData(t *testing.T) {
	c := newTestCollector(t)

	monitorEntry := &ldap.Entry{
		DN: "cn=monitor",
		Attributes: []*ldap.EntryAttribute{
			{Name: "bytessent", Values: []string{"999"}},
			// missing several attributes on purpose
			{Name: "version", Values: []string{"389-Directory/1.0"}},
		},
	}

	baseEntry := &ldap.Entry{
		DN: "dc=test,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "namingContexts", Values: []string{"dc=test,dc=com"}},
		},
	}

	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if req.BaseDN == "cn=monitor" {
				return &ldap.SearchResult{Entries: []*ldap.Entry{monitorEntry}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{baseEntry}}, nil
		},
	}
	c.dial = fakeDialer(mock)

	expected := `
		# HELP freeipa_ldap_base_search_success 1 if LDAP base search succeeded, 0 otherwise.
		# TYPE freeipa_ldap_base_search_success gauge
		freeipa_ldap_base_search_success{server="testhost"} 1
		# HELP freeipa_ldap_bytes_sent Number of bytes sent by the directory server since startup.
		# TYPE freeipa_ldap_bytes_sent gauge
		freeipa_ldap_bytes_sent{server="testhost"} 999
		# HELP freeipa_ldap_version_info Directory server version info.
		# TYPE freeipa_ldap_version_info gauge
		freeipa_ldap_version_info{server="testhost",version="389-Directory/1.0"} 1
	`

	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("metric mismatch: %v", err)
	}
}

func TestLdapCollectorCollectInvalidNumericValues(t *testing.T) {
	c := newTestCollector(t)

	monitorEntry := &ldap.Entry{
		DN: "cn=monitor",
		Attributes: []*ldap.EntryAttribute{
			{Name: "bytessent", Values: []string{"not-a-number"}},
			{Name: "threads", Values: []string{"24"}},
		},
	}

	baseEntry := &ldap.Entry{
		DN: "dc=test,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "namingContexts", Values: []string{"dc=test,dc=com"}},
		},
	}

	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if req.BaseDN == "cn=monitor" {
				return &ldap.SearchResult{Entries: []*ldap.Entry{monitorEntry}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{baseEntry}}, nil
		},
	}
	c.dial = fakeDialer(mock)

	expected := `
		# HELP freeipa_ldap_base_search_success 1 if LDAP base search succeeded, 0 otherwise.
		# TYPE freeipa_ldap_base_search_success gauge
		freeipa_ldap_base_search_success{server="testhost"} 1
		# HELP freeipa_ldap_threads Number of worker threads.
		# TYPE freeipa_ldap_threads gauge
		freeipa_ldap_threads{server="testhost"} 24
	`

	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("metric mismatch: %v", err)
	}
}

func TestLdapCollectorCollectInvalidStartTime(t *testing.T) {
	c := newTestCollector(t)

	monitorEntry := &ldap.Entry{
		DN: "cn=monitor",
		Attributes: []*ldap.EntryAttribute{
			{Name: "starttime", Values: []string{"invalid-time"}},
		},
	}

	baseEntry := &ldap.Entry{
		DN: "dc=test,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "namingContexts", Values: []string{"dc=test,dc=com"}},
		},
	}

	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if req.BaseDN == "cn=monitor" {
				return &ldap.SearchResult{Entries: []*ldap.Entry{monitorEntry}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{baseEntry}}, nil
		},
	}
	c.dial = fakeDialer(mock)

	expected := `
		# HELP freeipa_ldap_base_search_success 1 if LDAP base search succeeded, 0 otherwise.
		# TYPE freeipa_ldap_base_search_success gauge
		freeipa_ldap_base_search_success{server="testhost"} 1
	`

	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("metric mismatch: %v", err)
	}
}

func TestLdapCollectorCollectEmptyMonitorEntry(t *testing.T) {
	c := newTestCollector(t)

	baseEntry := &ldap.Entry{
		DN: "dc=test,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "namingContexts", Values: []string{"dc=test,dc=com"}},
		},
	}

	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if req.BaseDN == "cn=monitor" {
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{baseEntry}}, nil
		},
	}
	c.dial = fakeDialer(mock)

	expected := `
		# HELP freeipa_ldap_base_search_success 1 if LDAP base search succeeded, 0 otherwise.
		# TYPE freeipa_ldap_base_search_success gauge
		freeipa_ldap_base_search_success{server="testhost"} 1
	`

	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("metric mismatch: %v", err)
	}
}

func TestCheckLDAPSucceeds(t *testing.T) {
	c := newTestCollector(t)
	baseEntry := &ldap.Entry{
		DN: "dc=test,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "namingContexts", Values: []string{"dc=test,dc=com"}},
		},
	}
	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{baseEntry}}, nil
		},
	}
	c.dial = fakeDialer(mock)

	if !c.checkLDAP() {
		t.Error("expected checkLDAP to succeed")
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected 1 Close call, got %d", mock.closeCalls)
	}
}

func TestCheckLDAPDialFails(t *testing.T) {
	c := newTestCollector(t)
	c.dial = failingDialer(errors.New("dial error"))
	if c.checkLDAP() {
		t.Error("expected checkLDAP to fail")
	}
}

func TestCheckLDAPSearchFails(t *testing.T) {
	c := newTestCollector(t)
	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("search error")
		},
	}
	c.dial = fakeDialer(mock)
	if c.checkLDAP() {
		t.Error("expected checkLDAP to fail")
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected 1 Close call, got %d", mock.closeCalls)
	}
}

func TestCheckLDAPEmptyResult(t *testing.T) {
	c := newTestCollector(t)
	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c.dial = fakeDialer(mock)
	if c.checkLDAP() {
		t.Error("expected checkLDAP to fail")
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected 1 Close call, got %d", mock.closeCalls)
	}
}

func TestQueryMonitorSucceeds(t *testing.T) {
	c := newTestCollector(t)
	monitorEntry := &ldap.Entry{
		DN: "cn=monitor",
		Attributes: []*ldap.EntryAttribute{
			{Name: "threads", Values: []string{"16"}},
			{Name: "version", Values: []string{"389-Directory/1.4"}},
		},
	}
	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{monitorEntry}}, nil
		},
	}
	c.dial = fakeDialer(mock)

	attrs, err := c.queryMonitor()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attrs["threads"] != "16" {
		t.Errorf("expected threads=16, got %s", attrs["threads"])
	}
	if attrs["version"] != "389-Directory/1.4" {
		t.Errorf("expected version=389-Directory/1.4, got %s", attrs["version"])
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected 1 Close call, got %d", mock.closeCalls)
	}
}

func TestQueryMonitorDialFails(t *testing.T) {
	c := newTestCollector(t)
	c.dial = failingDialer(errors.New("dial failed"))
	attrs, err := c.queryMonitor()
	if err == nil {
		t.Fatal("expected error")
	}
	if attrs != nil {
		t.Error("expected nil attrs")
	}
}

func TestQueryMonitorSearchFails(t *testing.T) {
	c := newTestCollector(t)
	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("search failed")
		},
	}
	c.dial = fakeDialer(mock)
	attrs, err := c.queryMonitor()
	if err == nil {
		t.Fatal("expected error")
	}
	if attrs != nil {
		t.Error("expected nil attrs")
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected 1 Close call, got %d", mock.closeCalls)
	}
}

func TestQueryMonitorEmptyResult(t *testing.T) {
	c := newTestCollector(t)
	mock := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c.dial = fakeDialer(mock)
	attrs, err := c.queryMonitor()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attrs != nil {
		t.Error("expected nil attrs for empty result")
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected 1 Close call, got %d", mock.closeCalls)
	}
}
