package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	xff "github.com/stfsy/go-x-forwarded-for"
)

func main() {
	router := httprouter.New()

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Write([]byte("hello from " + r.RemoteAddr + "\n"))
	})

	xffmw, err := xff.Default()
	if err != nil {
		panic(err)
	}

	http.ListenAndServe(":8080", xffmw.Handler(router))
}
