package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	xff "github.com/stfsy/go-x-forwarded-for"
)

func main() {
	r := gin.Default()

	xffmw, err := xff.Default()
	if err != nil {
		panic(err)
	}

	r.Use(func(c *gin.Context) {
		xffmw.HandlerFunc(c.Writer, c.Request)
		c.Next()
	})

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "hello from "+c.Request.RemoteAddr+"\n")
	})

	r.Run(":8080")
}
