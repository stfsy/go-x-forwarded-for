package main

import (
	"net/http"

	xff "github.com/stfsy/go-x-forwarded-for"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from " + r.RemoteAddr + "\n"))
	})

	xffmw, err := xff.Default()
	if err != nil {
		panic(err)
	}

	http.ListenAndServe(":3000", xffmw.Handler(handler))
}
