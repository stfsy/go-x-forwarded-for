package main

import (
	"net/http"

	"github.com/gorilla/mux"
	xff "github.com/stfsy/go-x-forwarded-for"
)

func main() {
	r := mux.NewRouter()

	xffmw, err := xff.Default()
	if err != nil {
		panic(err)
	}

	r.Use(xffmw.Handler)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from " + r.RemoteAddr + "\n"))
	})

	http.ListenAndServe(":8080", r)
}
