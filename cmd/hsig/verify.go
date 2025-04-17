package main

import (
	"net/http"

	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyman"
)

func runVerifier() error {
	kf := keyman.NewKeyFetchInMemory(nil)
	verifier, err := httpsig.NewVerifier(kf, httpsig.DefaultVerifyProfile)
	if err != nil {
		return err
	}
	inspectHandler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte("Success!"))
	})
	vhandler := httpsig.NewHandler(inspectHandler, verifier)
	mux := http.NewServeMux()
	mux.Handle("/", vhandler)
	http.ListenAndServe(":3211", mux)
	return nil
}
