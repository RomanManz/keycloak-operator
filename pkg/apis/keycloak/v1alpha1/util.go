package v1alpha1

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	config2 "sigs.k8s.io/controller-runtime/pkg/client/config"
)

func UpdateStatusSecondaryResources(secondaryResources map[string][]string, kind string, resourceName string) map[string][]string {
	// If the map is nil, instansiate it
	if secondaryResources == nil {
		secondaryResources = make(map[string][]string)
	}

	// return if the resource name already exists in the slice
	for _, ele := range secondaryResources[kind] {
		if ele == resourceName {
			return secondaryResources
		}
	}
	// add the resource name to the list of secondary resources in the status
	secondaryResources[kind] = append(secondaryResources[kind], resourceName)

	// return new map
	return secondaryResources
}

// substitute userFederationProviders credentials from secret values
func CheckUserFederationProviderSecret(i *KeycloakRealmSpec, kc Keycloak, sgetter SecretKeyGetter) error {
outer:
	for _, ufps := range i.UserFederationProvidersSecrets {
		s, err := sgetter(ufps.SecretName, ufps.SecretKey, kc)
		if err != nil {
			return errors.Wrapf(err, "error retrieving %s from secret %s", ufps.UfpConfigKey, ufps.SecretName)
		}
		for _, p := range i.Realm.UserFederationProviders {
			if p.DisplayName == ufps.DisplayName {
				p.Config[ufps.UfpConfigKey] = s
				continue outer
			}
		}
		return errors.New(fmt.Sprintf("No UserFederationProvider %s found", ufps.DisplayName))
	}
	return nil
}

// get a secret from the cluster
func GetSecretKey(s, k string, kc Keycloak) (string, error) {
	config, err := config2.GetConfig()
	if err != nil {
		return "", err
	}

	secretClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}

	creds, err := secretClient.CoreV1().Secrets(kc.Namespace).Get(context.TODO(), s, v12.GetOptions{})
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get the %s credentials from secret %s", k, s))
	}
	v := string(creds.Data[k])
	if v == "" {
		return "", errors.New(fmt.Sprintf("empty value for %s from secret %s", k, s))
	}
	return v, nil
}

type SecretKeyGetter func(s, k string, kc Keycloak) (string, error)
