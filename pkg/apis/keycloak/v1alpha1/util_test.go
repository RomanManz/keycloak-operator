package v1alpha1

import (
	"errors"
	"fmt"
	"testing"
)

func TestCheckUserFederationProviderSecretOk(t *testing.T) {
	sf := &secretFake{map[string]*sFake{
		"secretOne": {
			keys: map[string]string{
				"foo": "bar",
			},
		},
	}}
	testSecretGetter := getSecretKeyGetter(sf)
	testRealmSpec := &KeycloakRealmSpec{
		UserFederationProvidersSecrets: []*UserFederationProvidersSecret{
			&UserFederationProvidersSecret{
				DisplayName:  "test-ldap",
				SecretName:   "secretOne",
				SecretKey:    "foo",
				UfpConfigKey: "bindCredential",
			},
		},
		Realm: &KeycloakAPIRealm{
			Realm: "test",
			UserFederationProviders: []*KeycloakAPIUserFederationProvider{
				&KeycloakAPIUserFederationProvider{
					DisplayName: "test-ldap",
					Config: map[string]string{
						"bindCredential": "__none__",
					},
				},
			},
		},
	}
	if err := testRealmSpec.CheckUserFederationProviderSecret(Keycloak{}, testSecretGetter); err != nil {
		t.Error(fmt.Sprintf("expected no error but got '%s'", err.Error()))
	} else if testRealmSpec.Realm.UserFederationProviders[0].Config["bindCredential"] != "bar" {
		t.Error(fmt.Sprintf("expected the bindCredential value to be 'bar' but got '%s' instead", testRealmSpec.Realm.UserFederationProviders[0].Config["bindCredential"]))
	}
}

func TestCheckUserFederationProviderSecretKo(t *testing.T) {
	sf := &secretFake{map[string]*sFake{
		"secretOne": {
			keys: map[string]string{
				"foo": "bar",
			},
		},
	}}
	testSecretGetter := getSecretKeyGetter(sf)
	testRealmSpecNoSecret := &KeycloakRealmSpec{
		UserFederationProvidersSecrets: []*UserFederationProvidersSecret{
			&UserFederationProvidersSecret{
				DisplayName:  "test-ldap",
				SecretName:   "secretZero",
				SecretKey:    "foo",
				UfpConfigKey: "bindCredential",
			},
		},
		Realm: &KeycloakAPIRealm{
			Realm: "test",
			UserFederationProviders: []*KeycloakAPIUserFederationProvider{
				&KeycloakAPIUserFederationProvider{
					DisplayName: "test-ldap",
					Config: map[string]string{
						"bindCredential": "__none__",
					},
				},
			},
		},
	}
	missingSecretError := "error retrieving bindCredential from secret secretZero: no secret secretZero found"
	if err := testRealmSpecNoSecret.CheckUserFederationProviderSecret(Keycloak{}, testSecretGetter); err == nil {
		t.Error("expected error from unknown secret but got none")
	} else if err.Error() != missingSecretError {
		t.Error(fmt.Sprintf("expected error '%s' but got '%s' instead", missingSecretError, err.Error()))
	}
	testRealmSpecNoKey := &KeycloakRealmSpec{
		UserFederationProvidersSecrets: []*UserFederationProvidersSecret{
			&UserFederationProvidersSecret{
				DisplayName:  "test-ldap",
				SecretName:   "secretOne",
				SecretKey:    "baz",
				UfpConfigKey: "bindCredential",
			},
		},
		Realm: &KeycloakAPIRealm{
			Realm: "test",
			UserFederationProviders: []*KeycloakAPIUserFederationProvider{
				&KeycloakAPIUserFederationProvider{
					DisplayName: "testfoo-ldap",
					Config: map[string]string{
						"bindCredential": "__none__",
					},
				},
			},
		},
	}
	missingKeyError := "error retrieving bindCredential from secret secretOne: no key baz found in secret secretOne"
	if err := testRealmSpecNoKey.CheckUserFederationProviderSecret(Keycloak{}, testSecretGetter); err == nil {
		t.Error("expected error from unknown key but got none")
	} else if err.Error() != missingKeyError {
		t.Error(fmt.Sprintf("expected error '%s' but got '%s' instead", missingKeyError, err.Error()))
	}
	testRealmSpecNoUfp := &KeycloakRealmSpec{
		UserFederationProvidersSecrets: []*UserFederationProvidersSecret{
			&UserFederationProvidersSecret{
				DisplayName:  "test-ldap",
				SecretName:   "secretOne",
				SecretKey:    "foo",
				UfpConfigKey: "bindCredential",
			},
		},
		Realm: &KeycloakAPIRealm{
			Realm: "test",
			UserFederationProviders: []*KeycloakAPIUserFederationProvider{
				&KeycloakAPIUserFederationProvider{
					DisplayName: "testfoo-ldap",
					Config: map[string]string{
						"bindCredential": "__none__",
					},
				},
			},
		},
	}
	missingUfpError := "No UserFederationProvider test-ldap found"
	if err := testRealmSpecNoUfp.CheckUserFederationProviderSecret(Keycloak{}, testSecretGetter); err == nil {
		t.Error("expected error from unknown ufp but got none")
	} else if err.Error() != missingUfpError {
		t.Error(fmt.Sprintf("expected error '%s' but got '%s' instead", missingUfpError, err.Error()))
	}
}

// helpers
type secretFake struct {
	fakes map[string]*sFake
}

type sFake struct {
	keys map[string]string
}

func getSecretKeyGetter(f *secretFake) SecretKeyGetter {
	return func(s, k string, kc Keycloak) (string, error) {
		_s := f.fakes[s]
		if _s == nil {
			return "", errors.New(fmt.Sprintf("no secret %s found", s))
		}
		_v := _s.keys[k]
		if _v == "" {
			return "", errors.New(fmt.Sprintf("no key %s found in secret %s", k, s))
		}
		return _v, nil
	}
}
