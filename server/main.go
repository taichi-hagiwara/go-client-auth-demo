package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/pkg/errors"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		fmt.Fprintf(w, "Hello, %s!!", cert.Subject.CommonName)
	}
}

func main() {
	http.HandleFunc("/", handler)

	certPool, err := clientCAs()
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  certPool,
	}
	tlsConfig.BuildNameToCertificate()

	server := &http.Server{
		TLSConfig: tlsConfig,
		Addr:      "localhost:8080",
	}

	if err := server.ListenAndServeTLS("cert.pem", "private.pem"); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func clientCAs() (*x509.CertPool, error) {
	cert, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		return nil, errors.Wrap(err, "failed to read ca.pem")
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		return nil, errors.New("failed to append cert from .pem")
	}

	return certPool, nil
}
