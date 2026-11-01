package main

import (
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	xff "github.com/stfsy/go-x-forwarded-for"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from " + r.RemoteAddr + "\n"))
	})

	r := mux.NewRouter()
	r.Handle("/", handler)

	n := negroni.Classic()
	xffmw, err := xff.Default()
	if err != nil {
		panic(err)
	}
	n.Use(xffmw)
	n.UseHandler(r)
	n.Run(":3000")
}
