package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/babolivier/go-doh-client"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/vitrevance/quicer/quicer"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "Address to listen connections on.")
	cert := flag.String("cert", "", "Path to root certificate")
	certKey := flag.String("key", "", "Path to root certificate private key")
	flag.Parse()

	var parentCert *quicer.ParentCertificateConfig
	if *cert != "" {
		if *certKey != "" {
			rootCert, rootKey, err := quicer.LoadCertificate(*cert, *certKey)
			if err != nil {
				log.Fatalf("Failed to load root certificate: %v", err)
			}
			parentCert = &quicer.ParentCertificateConfig{
				Cert: rootCert,
				Key:  rootKey,
			}
		} else {
			log.Fatal("Provide both --cert and --key or neither")
		}
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	quicRT := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: false,
			// MinVersion:         tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{
			Tracer:            qlog.DefaultConnectionTracer,
			EnableDatagrams:   true,
			InitialPacketSize: 1201,
			// Versions: []quic.Version{
			// 	quic.Version2,
			// },
		},
		EnableDatagrams: true,
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		Dial: Dial,
	}

	// roundTripper := &cronet.RoundTripper{}

	server, err := quicer.NewHttpProxy(*addr, quicRT, &quicer.CachedCertificateProvider{
		CA:          *parentCert,
		StoragePath: "./certs/",
	})
	if err != nil {
		panic(err)
	}

	server.Start(context.Background())
}

func Dial(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
	domain, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %v", err)
	}

	// Resolve domain using DoH
	resolver := doh.Resolver{
		Host:  "dns.google",
		Class: doh.IN,
	}
	aRecords, _, err := resolver.LookupAAAA(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %v", domain, err)
	}

	if len(aRecords) == 0 {
		return nil, fmt.Errorf("no IP addresses found for domain %s", domain)
	}

	// Use first resolved IP address
	dnsResp := ""
	switch ip := (any)(aRecords[0]).(type) {
	case *doh.ARecord:
		dnsResp = ip.IP4
	case *doh.AAAARecord:
		dnsResp = ip.IP6
	}
	ip := net.ParseIP(dnsResp)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", dnsResp)
	}

	// Reconstruct address with resolved IP
	resolvedAddr := fmt.Sprintf("%s:%s", ip.String(), port)

	tlsCfg.ServerName = domain

	// Dial using resolved IP address
	conn, err := quic.DialAddrEarly(ctx, resolvedAddr, tlsCfg, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to dial QUIC address %s: %v", resolvedAddr, err)
	}
	return conn, nil
}
