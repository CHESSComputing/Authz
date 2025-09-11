package main

// server module
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//
import (
	"database/sql"
	"log"
	"net/http"
	"os"

	srvConfig "github.com/CHESSComputing/golib/config"
	ldap "github.com/CHESSComputing/golib/ldap"
	server "github.com/CHESSComputing/golib/server"
	services "github.com/CHESSComputing/golib/services"
	sqldb "github.com/CHESSComputing/golib/sqldb"
	"github.com/gin-gonic/gin"

	// kerberos auth
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
)

// examples: https://go.dev/doc/tutorial/web-service-gin

// _DB defines sql DB pointer
var _DB *sql.DB

// Verbose flag to use
var Verbose int

// keep ldap cache
var ldapCache *ldap.Cache
var _foxdenUser services.UserAttributes

// helper function to define our login handler
func loginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		LoginHandler(c.Writer, c.Request)
		c.Next()
	}
}

// helper function to setup our server router
func setupRouter() *gin.Engine {

	routes := []server.Route{
		{Method: "GET", Path: "/oauth/token", Handler: TokenHandler, Authorized: false},
		{Method: "GET", Path: "/attrs", Handler: AttributesHandler, Authorized: true},
		//         {Method: "GET", Path: "/kauth", Handler: KAuthHandler, Authorized: false},
		{Method: "POST", Path: "/kauth", Handler: KAuthHandler, Authorized: false},
		{Method: "POST", Path: "/oauth/authorize", Handler: ClientAuthHandler, Authorized: false},
		{Method: "POST", Path: "/oauth/trusted", Handler: TrustedHandler, Authorized: false},
		{Method: "POST", Path: "/trusted_client", Handler: TrustedClientHandler, Authorized: false},
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
			server.Route{Method: "GET", Path: "/", Handler: loginHandler(), Authorized: false})
	}
	r := server.Router(routes, StaticFs, "static", srvConfig.Config.Authz.WebServer)
	return r
}

// Server defines our HTTP server
func Server() {
	dbtype, dburi, dbowner := sqldb.ParseDBFile(srvConfig.Config.Authz.DBFile)
	log.Printf("InitDB: type=%s owner=%s", dbtype, dbowner)
	db, err := sqldb.InitDB(dbtype, dburi)
	if err != nil {
		log.Fatal(err)
	}
	_DB = db
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// initialize ldap cache
	ldapCache = &ldap.Cache{Map: make(map[string]ldap.Entry)}

	// make a choice of foxden user
	switch srvConfig.Config.CHESSMetaData.FoxdenUser.User {
	case "Maglab":
		_foxdenUser = &services.MaglabUser{}
	case "CHESS":
		_foxdenUser = &services.CHESSUser{}
	default:
		_foxdenUser = &services.CHESSUser{}
	}
	_foxdenUser.Init()

	// setup web router and start the service
	r := setupRouter()
	webServer := srvConfig.Config.Authz.WebServer
	Verbose = webServer.Verbose
	server.StartServer(r, webServer)
}
