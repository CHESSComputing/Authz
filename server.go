package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	srvConfig "github.com/CHESSComputing/golib/config"
	srvServer "github.com/CHESSComputing/golib/server"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"

	// kerberos auth
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
)

// examples: https://go.dev/doc/tutorial/web-service-gin

// _DB defines gorm DB pointer
var _DB *gorm.DB

var _oauthServer *server.Server

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
	r := srvServer.Router(routes, StaticFs, "static",
		srvConfig.Config.Authz.WebServer.Base,
		srvConfig.Config.Authz.WebServer.Verbose,
	)
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

	// setup oauth parts
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(
		generates.NewJWTAccessGenerate(
			"", []byte(srvConfig.Config.Authz.ClientID), jwt.SigningMethodHS512))
	//     manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	clientStore.Set(srvConfig.Config.Authz.ClientID, &models.Client{
		ID:     srvConfig.Config.Authz.ClientID,
		Secret: srvConfig.Config.Authz.ClientSecret,
		Domain: srvConfig.Config.Authz.Domain,
	})
	manager.MapClientStorage(clientStore)
	_oauthServer = server.NewServer(server.NewConfig(), manager)
	_oauthServer.SetAllowGetAccessRequest(true)
	_oauthServer.SetClientInfoHandler(server.ClientFormHandler)

	r := setupRouter()
	sport := fmt.Sprintf(":%d", srvConfig.Config.Authz.WebServer.Port)
	log.Printf("Start HTTP server %s", sport)
	r.Run(sport)
}
