package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/pkg/errors"
)

func rootCAs() (*x509.CertPool, error) {
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

func main() {
	req, err := http.NewRequest("GET", "https://localhost:8080", nil)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := tls.LoadX509KeyPair("cert.pem", "private.pem")
	if err != nil {
		log.Fatal(err)
	}

	certPool, err := rootCAs()
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	client := &http.Client{Transport: transport}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(resp.StatusCode)

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(b))
}
