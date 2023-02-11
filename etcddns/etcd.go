package etcddns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	etcdcv3 "go.etcd.io/etcd/client/v3"
)

// Almost all of this file was borrowed from https://github.com/kubernetes-sigs/external-dns/blob/master/provider/coredns/coredns.go

const (
	priority    = 10 // default priority when nothing is set
	etcdTimeout = 5 * time.Second
)

type EtcdDnsClient struct {
	client *etcdcv3.Client
}

// Service represents CoreDNS etcd record
type Service struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Weight   int    `json:"weight,omitempty"`
	Text     string `json:"text,omitempty"`
	Mail     bool   `json:"mail,omitempty"` // Be an MX record. Priority becomes Preference.
	TTL      uint32 `json:"ttl,omitempty"`

	// When a SRV record with a "Host: IP-address" is added, we synthesize
	// a srv.Target domain name.  Normally we convert the full Key where
	// the record lives to a DNS name and use this as the srv.Target.  When
	// TargetStrip > 0 we strip the left most TargetStrip labels from the
	// DNS name.
	TargetStrip int `json:"targetstrip,omitempty"`

	// Group is used to group (or *not* to group) different services
	// together. Services with an identical Group are returned in the same
	// answer.
	Group string `json:"group,omitempty"`

	// Etcd key where we found this service and ignored from json un-/marshaling
	Key string `json:"-"`
}

// GetService return all Service records stored in etcd stored anywhere under the given key (recursively)
func (c EtcdDnsClient) GetServices(prefix string, ctx context.Context) ([]*Service, error) {
	ctx, cancel := context.WithTimeout(ctx, etcdTimeout)
	defer cancel()

	path := prefix
	r, err := c.client.Get(ctx, path, etcdcv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	var svcs []*Service
	bx := make(map[Service]bool)
	for _, n := range r.Kvs {
		svc := new(Service)
		if err := json.Unmarshal(n.Value, svc); err != nil {
			return nil, fmt.Errorf("%s: %s", n.Key, err.Error())
		}
		b := Service{Host: svc.Host, Port: svc.Port, Priority: svc.Priority, Weight: svc.Weight, Text: svc.Text, Key: string(n.Key)}
		if _, ok := bx[b]; ok {
			// skip the service if already added to service list.
			// the same service might be found in multiple etcd nodes.
			continue
		}
		bx[b] = true

		svc.Key = string(n.Key)
		if svc.Priority == 0 {
			svc.Priority = priority
		}
		svcs = append(svcs, svc)
	}

	return svcs, nil
}

// SaveService persists service data into etcd
func (c EtcdDnsClient) SaveService(service *Service, ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, etcdTimeout)
	defer cancel()

	value, err := json.Marshal(&service)
	if err != nil {
		return err
	}
	log.Infof("value=%s", string(value))
	_, err = c.client.Put(ctx, service.Key, string(value))
	if err != nil {
		return err
	}
	return nil
}

// DeleteService deletes service record from etcd
func (c EtcdDnsClient) DeleteService(key string, ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, etcdTimeout)
	defer cancel()

	_, err := c.client.Delete(ctx, key, etcdcv3.WithPrefix())
	return err
}

func reverse(slice []string) {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
}
func Key(prefix string, dnsName string) string {
	domains := strings.Split(dnsName, ".")
	reverse(domains)
	return prefix + strings.Join(domains, "/")
}

// builds etcd client config depending on connection scheme and TLS parameters
// borrowed from  to keep config simple
func getenvEtcdConfig() (*etcdcv3.Config, error) {
	etcdURLsStr := os.Getenv("ETCD_URLS")
	if etcdURLsStr == "" {
		etcdURLsStr = "http://localhost:2379"
	}
	etcdURLs := strings.Split(etcdURLsStr, ",")
	firstURL := strings.ToLower(etcdURLs[0])
	if strings.HasPrefix(firstURL, "http://") {
		return &etcdcv3.Config{Endpoints: etcdURLs}, nil
	} else if strings.HasPrefix(firstURL, "https://") {
		caFile := os.Getenv("ETCD_CA_FILE")
		certFile := os.Getenv("ETCD_CERT_FILE")
		keyFile := os.Getenv("ETCD_KEY_FILE")
		serverName := os.Getenv("ETCD_TLS_SERVER_NAME")
		isInsecureStr := strings.ToLower(os.Getenv("ETCD_TLS_INSECURE"))
		isInsecure := isInsecureStr == "true" || isInsecureStr == "yes" || isInsecureStr == "1"
		tlsConfig, err := newTLSConfig(certFile, keyFile, caFile, serverName, isInsecure)
		if err != nil {
			return nil, err
		}
		return &etcdcv3.Config{
			Endpoints: etcdURLs,
			TLS:       tlsConfig,
		}, nil
	} else {
		return nil, errors.New("etcd URLs must start with either http:// or https://")
	}
}

// loads CA cert
func loadRoots(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}

	roots := x509.NewCertPool()
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %s", caPath, err)
	}
	ok := roots.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("could not read root certs: %s", err)
	}
	return roots, nil
}

// loads TLS artifacts and builds tls.Config object
func newTLSConfig(certPath, keyPath, caPath, serverName string, insecure bool) (*tls.Config, error) {
	if certPath != "" && keyPath == "" || certPath == "" && keyPath != "" {
		return nil, errors.New("either both cert and key or none must be provided")
	}
	var certificates []tls.Certificate
	if certPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("could not load TLS cert: %s", err)
		}
		certificates = append(certificates, cert)
	}
	roots, err := loadRoots(caPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:       certificates,
		RootCAs:            roots,
		InsecureSkipVerify: insecure,
		ServerName:         serverName,
	}, nil
}

func NewEtcdDnsClient() (*EtcdDnsClient, error) {

	cfg, err := getenvEtcdConfig()
	if err != nil {
		return nil, err
	}
	c, err := etcdcv3.New(*cfg)
	if err != nil {
		return nil, err
	}
	return &EtcdDnsClient{c}, nil
}
