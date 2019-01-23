// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"gopkg.in/ldap.v2"
)

type LDAPClient struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
}

// Connect connects to the ldap backend.
func (lc *LDAPClient) Connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection.
func (lc *LDAPClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, error) {

	userSearchResult, err := lc.doSearch(fmt.Sprintf(lc.UserFilter, username), append(lc.Attributes, "dn"))

	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return false, user, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, user, err
		}
	}

	return true, user, nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *LDAPClient) GetGroupsOfUser(username string) ([]string, error) {
	dnSearchResult, err := lc.doSearch(fmt.Sprintf(lc.UserFilter, username), []string{"dn"})
	if err != nil {
		return nil, err
	}

	if len(dnSearchResult.Entries) != 1 {
		return nil, errors.New("User does not exist")
	}

	userdn := dnSearchResult.Entries[0].DN

	groupSearchResult, err := lc.doSearch(fmt.Sprintf(lc.GroupFilter, userdn), []string{"cn"})

	if err != nil {
		return nil, err
	}

	groups := []string{}
	for _, entry := range groupSearchResult.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

	return groups, nil
}

// GetAllUsers returns all users
func (lc *LDAPClient) GetAllUsers(userField string) ([]string, error) {
	usersSearchResult, err := lc.doSearch("(&(objectCategory=person)(objectClass=user))", []string{userField})

	if err != nil {
		return nil, err
	}

	users := []string{}

	for _, entry := range usersSearchResult.Entries {
		users = append(users, entry.GetAttributeValue(userField))
	}

	return users, nil
}

// GetAllGroups returns all the available groups
func (lc *LDAPClient) GetAllGroups() ([]string, error) {
	grousSearchResult, err := lc.doSearch("(objectCategory=group)", []string{"cn"})

	if err != nil {
		return nil, err
	}

	groups := []string{}

	for _, entry := range grousSearchResult.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

	return groups, nil
}

func (lc *LDAPClient) doSearch(filter string, attributes []string) (*ldap.SearchResult, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}
	defer lc.Close()

	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return nil, err
		}
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)

	if err != nil {
		return nil, err
	}

	return sr, nil
}
