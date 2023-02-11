# cert-manager DNS-01 webhook for CoreDNS via etcd

This is a [cert-manager webhook](https://cert-manager.io/docs/configuration/acme/dns01/webhook/) handler generates DNS records for ACME DNS-01 challenges in the etcd schema expected by CoreDNS's [etcd plugin](https://coredns.io/plugins/etcd/). This allows a single public-facing CoreDNS and etcd instance to serve both [external-dns](https://github.com/kubernetes-sigs/external-dns/) and cert-manager records.

This repository is based on https://github.com/cert-manager/webhook-example.
