package etcddns

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	log "github.com/sirupsen/logrus"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Solver struct {
	client *kubernetes.Clientset
	prefix string
}

func (c *Solver) Name() string {
	return "etcddns-webhook"
}

func (c *Solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl

	return nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
func (c *Solver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	service := Service{
		Key:  Key(cfg.Prefix, ch.ResolvedFQDN),
		Text: ch.Key,
	}

	log.Infof("Add %s TXT=%s", service.Key, service.Text)

	client, err := NewEtcdDnsClient()
	if err != nil {
		log.Fatal(err)
	}

	client.SaveService(&service, context.Background())

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// TODO: If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently
func (c *Solver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	key := Key(cfg.Prefix, ch.ResolvedFQDN)
	log.Infof("Delete %s", key)

	client, err := NewEtcdDnsClient()
	if err != nil {
		log.Fatal(err)
	}
	client.DeleteService(key, context.Background())

	return nil
}

type etcdProviderConfig struct {
	Prefix string `json:"prefix"`
}

func loadConfig(cfgJSON *extapi.JSON) (etcdProviderConfig, error) {
	cfg := etcdProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
