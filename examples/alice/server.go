package main

import (
	"net/http"

	"github.com/justinas/alice"
	xff "github.com/stfsy/go-x-forwarded-for"
)

func main() {
	xffmw, err := xff.Default()
	if err != nil {
		panic(err)
	}

	chain := alice.New(xffmw.Handler)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from " + r.RemoteAddr + "\n"))
	})

	http.ListenAndServe(":8080", chain.Then(handler))
}
