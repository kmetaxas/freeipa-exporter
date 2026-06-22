package main

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v2"
)

type Config struct {
	Kerberos KerberosConfig `yaml:"kerberos" json:"kerberos"`
	Ldap     LdapConfig     `yaml:"ldap" json:"yaml"`
}

type KerberosConfig struct {
	Krb5ConfPath string `yaml:"krb5confPath" json:"krb5confPath"`
	Principal    string `yaml:"principal" json:"principal"`
	KeytabPath   string `yaml:"keytabPath" json:"keytabPath"`
	Realm        string `yaml:"realm" json:"realm"`
}

type LdapConfig struct {
	LdapUrl string `yaml:"ldapUrl" json:"ldapUrl"`
	// This should normally not be overriden but lets give the user the flexibility.
	LdapQuery string `yaml:"ldapQuery" json:"ldapQuery"`
	BaseDN    string `yaml:"baseDN" json:"baseDN"`
	CAPath    string `yaml:"caPath" json:"caPath"`
}

func newConfig() (*Config, error) {
	var err error = nil
	config := Config{}
	data, err := os.ReadFile("freeipa_exporter.yaml")
	if err != nil {
		return nil, err
	}
	yaml.Unmarshal(data, &config)
	fmt.Printf("config = %v+", config)
	return &config, err
}

/* return v if not empty. return d otherwise */
func value_or_default(v string, d string) string {
	if v != "" {
		return v
	}
	return d
}
