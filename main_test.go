package main

import (
	"os"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
	"github.com/kleinpa/cert-manager-etcddns-webhook/etcddns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {

	// solver := example.New("59351")
	fixture := dns.NewFixture(&etcddns.Solver{},
		dns.SetResolvedZone(zone),
		dns.SetManifestPath("testdata/etcddns-solver"),
		dns.SetAllowAmbientCredentials(false),
	)
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
