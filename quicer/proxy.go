package quicer

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sync"
)

type httpProxy struct {
	server              *http.Server
	tlsConfig           *tls.Config
	certificateProvider CertificateProvider
	roundTripper        http.RoundTripper
	mux                 sync.Mutex
}

func NewHttpProxy(addr string, roundTripper http.RoundTripper, certProvider CertificateProvider) (*httpProxy, error) {
	proxy := &httpProxy{
		certificateProvider: certProvider,
	}
	server := &http.Server{
		Addr:    addr,
		Handler: proxy,
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	proxy.server = server
	proxy.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		GetCertificate: proxy.getCertificate,
	}
	proxy.roundTripper = roundTripper
	return proxy, nil
}

func (p *httpProxy) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	go func() {
		cancel(p.server.ListenAndServe())
	}()
	<-ctx.Done()
	return p.server.Shutdown(ctx)
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)
	} else {
		r.Header.Del("connection")
		r.Header.Del("via")
		resp, err := p.roundTripper.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (p *httpProxy) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.certificateProvider.Get(clientHello.ServerName)
}

func (p *httpProxy) handleTunneling(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	conn := tls.Server(client_conn, p.tlsConfig)
	serverName := conn.ConnectionState().ServerName
	go http.Serve(&SingleConnectionListener{
		Conn: conn,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.OmitHost = false
		r.URL.Scheme = "https"
		if serverName == "" {
			r.URL.Host = r.Host
		} else {
			r.URL.Host = serverName
		}
		r.Header.Del("connection")
		p.ServeHTTP(w, r)
	}))
}
