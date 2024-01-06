package main

// server module
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//
import (
	"fmt"
	"log"
	"net/http"
	"os"

	srvConfig "github.com/CHESSComputing/golib/config"
	server "github.com/CHESSComputing/golib/server"
	srvServer "github.com/CHESSComputing/golib/server"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	// kerberos auth
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
)

// examples: https://go.dev/doc/tutorial/web-service-gin

// _DB defines gorm DB pointer
var _DB *gorm.DB

// helper function to define our login handler
func loginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		LoginHandler(c.Writer, c.Request)
		c.Next()
	}
}

// helper function to setup our server router
func setupRouter() *gin.Engine {

	routes := []srvServer.Route{
		srvServer.Route{Method: "GET", Path: "/oauth/token", Handler: TokenHandler, Authorized: false},
		srvServer.Route{Method: "GET", Path: "/kauth", Handler: KAuthHandler, Authorized: false},
		srvServer.Route{Method: "POST", Path: "/kauth", Handler: KAuthHandler, Authorized: false},
		srvServer.Route{Method: "POST", Path: "/oauth/authorize", Handler: ClientAuthHandler, Authorized: false},
	}
	if srvConfig.Config.Kerberos.Keytab != "" {
		kt, err := keytab.Load(srvConfig.Config.Kerberos.Keytab)
		if err != nil {
			log.Fatal(err)
		}
		l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
		h := http.HandlerFunc(LoginHandler)
		http.Handle("/", spnego.SPNEGOKRB5Authenticate(h, kt, service.Logger(l)))
	} else {
		routes = append(routes,
			srvServer.Route{Method: "GET", Path: "/", Handler: loginHandler(), Authorized: false})
	}
	r := srvServer.Router(routes, StaticFs, "static", srvConfig.Config.Authz.WebServer)
	r.Use(server.CounterMiddleware())
	return r
}

// Server defines our HTTP server
func Server() {
	db, err := initDB("sqlite")
	if err != nil {
		log.Fatal(err)
	}
	_DB = db
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	r := setupRouter()
	sport := fmt.Sprintf(":%d", srvConfig.Config.Authz.WebServer.Port)
	log.Printf("Start HTTP server %s", sport)
	r.Run(sport)
}
