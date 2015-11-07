package main

import (
	"log"
	"net/http"
	"path/filepath"
)

func main() {
	certFile, _ := filepath.Abs("../certificate/x509/ecdsa/certs/server.pem")
	keyFile, _ := filepath.Abs("../certificate/x509/ecdsa/certs/server-key.pem")

	http.HandleFunc("/", rootHandler)

	port := "3000"
	log.Printf("[INFO] Start listen on %s", port)
	// http.ListenAndServeTLS calls tls.LoadX509KeyPair(certFile, keyFile)
	err := http.ListenAndServeTLS("localhost:"+port, certFile, keyFile, nil)

	if err != nil {
		log.Printf("[ERROR] %s", err)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] Request from %s", r.RemoteAddr)
	w.Header().Set("Content-type", "text/plain")
	w.Write([]byte("Hello with TLS\n"))
}
