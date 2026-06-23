package main

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v2"
)

type Config struct {
	Kerberos KerberosConfig `yaml:"kerberos" json:"kerberos"`
	Ldap     LdapConfig     `yaml:"ldap" json:"yaml"`
	Exporter ExporterConfig `yaml:"exporter" json:"exporter"`
}
type ExporterConfig struct {
	ListenAddr string `yaml:"listenAddr" json:"listenAddr"`
	ListenPort string `yaml:"port" json:"port"`
}

type KerberosConfig struct {
	Krb5ConfPath string `yaml:"krb5confPath" json:"krb5confPath"`
	KdcLogPath   string `yaml:"kdcLogPath" json:"kdcLogPath"`
	Username     string `yaml:"username" json:"username"`
	KeytabPath   string `yaml:"keytabPath" json:"keytabPath"`
	Realm        string `yaml:"realm" json:"realm"`
	Password     string `yaml:"password" json:"password"`
}

type LdapConfig struct {
	LdapUrl string `yaml:"ldapUrl" json:"ldapUrl"`
	// This should normally not be overriden but lets give the user the flexibility.
	LdapQuery string `yaml:"ldapQuery" json:"ldapQuery"`
	BaseDN    string `yaml:"baseDN" json:"baseDN"`
	CAPath    string `yaml:"caPath" json:"caPath"`
}

func NewConfig() (*Config, error) {
	var err error = nil
	config := Config{}
	data, err := os.ReadFile("freeipa_exporter.yaml")
	if err != nil {
		return nil, err
	}
	yaml.Unmarshal(data, &config)
	if config.Exporter.ListenPort == "" {
		config.Exporter.ListenPort = "9195"
	}
	// make sure either keytab or password defined, but not both
	if config.Kerberos.Password != "" && config.Kerberos.Krb5ConfPath != "" {
		return &config, fmt.Errorf("Either password or keytab must be defined, but not both!")
	}
	if config.Kerberos.KdcLogPath == "" {
		config.Kerberos.KdcLogPath = "/var/log/krb5kdc.log"
	}
	return &config, err
}

/* return v if not empty. return d otherwise */
func Value_or_default(v string, d string) string {
	if v != "" {
		return v
	}
	return d
}
