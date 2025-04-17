package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyutil"
	"gopkg.in/elazarl/goproxy.v1"
)

func main() {
	action := flag.String("action", "sign", "sign or verify")
	//	msgFile := flag.String("file", "", "file")
	//	msgType := flag.String("type", "request", "request or response")
	privKeyFile := flag.String("key", "", "private key file")
	algorithm := flag.String("alg", string(httpsig.Algo_ECDSA_P256_SHA256), "The algorithm to sign with. The 'alg' parameter in the signature profile, if present, must match this algorithm")
	sig := flag.String("sig", "", "Signature")
	flag.Parse()

	so, err := httpsig.ParseAcceptSignature(*sig)
	if err != nil {
		panic(err)
	}
	so.Algorithm = httpsig.Algorithm(*algorithm)
	so.PrivateKey = keyutil.MustReadPrivateKeyFile(*privKeyFile)
	signer, err := httpsig.NewSigner(so)
	if err != nil {
		panic(err)
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			r.Header.Set("Authorization", "REMV1-ECDSA-P256-SHA256")
			err := signer.Sign(r)
			if err != nil {
				log.Fatal(err)
			}
			ctx.Logf("Signature: %s", r.Header.Get("Signature"))
			ctx.Logf("Signature-Input: %s", r.Header.Get("Signature-Input"))
			ctx.Logf("Content-Digest: %s", r.Header.Get("Content-Digest"))
			ctx.Logf("target-uri: %s", r.RequestURI)
			return r, nil
		})
	log.Fatal(http.ListenAndServe(":8081", proxy))

	/*
		data, err := os.Open(*msgFile)
		if err != nil {
			panic(err)
		}
		req, err := http.ReadRequest(bufio.NewReader(data))
		if err != nil {
			panic(err)
		}


		err = signer.Sign(req)
		if err != nil {
			panic(err)
		}
		out, err := httputil.DumpRequest(req, true)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(out))
	*/
}

func signingProxy() {
}
