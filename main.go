package main

import (
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"

	"github.com/kleinpa/cert-manager-etcddns-webhook/etcddns"
)

const (
	priority = 10 // default priority when nothing is set
)

func main() {
	var group = os.Getenv("GROUP_NAME")
	if group == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(group, &etcddns.Solver{})
}
