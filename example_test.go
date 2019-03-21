package ldap_test

import (
	"log"

	"github.com/joffcom/go-ldap-client"
)

// ExampleLDAPClient_Authenticate shows how a typical application can verify a login attempt
func ExampleLDAPClient_Authenticate() {
	client := setupClient()

	ok, user, err := client.Authenticate("username", "password")
	if err != nil {
		log.Fatalf("Error authenticating user %s: %+v", "username", err)
	}
	if !ok {
		log.Fatalf("Authenticating failed for user %s", "username")
	}
	log.Printf("User: %+v", user)

}

// ExampleLDAPClient_GetGroupsOfUser shows how to retrieve user groups
func ExampleLDAPClient_GetGroupsOfUser() {
	client := setupClient()

	groups, err := client.GetGroupsOfUser("username")
	if err != nil {
		log.Fatalf("Error getting groups for user %s: %+v", "username", err)
	}
	log.Printf("Groups: %+v", groups)
}

// ExampleLDAPClient_GetAllUsers shows how to retrieve all users
func ExampleLDAPClient_GetAllUsers() {
	client := setupClient()

	users, err := client.GetAllUsers("sAMAccountName")
	if err != nil {
		log.Fatalf("Error getting users: %+v", err)
	}
	log.Printf("Users: %+v", users)
}

// ExampleLDAPClient_GetAllGroups shows how to retrieve all groups
func ExampleLDAPClient_GetAllGroups() {
	client := setupClient()

	groups, err := client.GetAllGroups()
	if err != nil {
		log.Fatalf("Error getting groups: %+v", err)
	}
	log.Printf("Groups: %+v", groups)
}

func setupClient() *ldap.LDAPClient {
	client := &ldap.LDAPClient{
		Base:         "dc=example,dc=com",
		Host:         "ldap.example.com",
		Port:         389,
		PageSize:     500,
		UseSSL:       false,
		BindDN:       "uid=readonlysuer,ou=People,dc=example,dc=com",
		BindPassword: "readonlypassword",
		UserFilter:   "(uid=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}
	defer client.Close()
	return client
}
