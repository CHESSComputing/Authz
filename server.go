package main

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"

	srvConfig "github.com/CHESSComputing/golib/config"
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

var _routes gin.RoutesInfo
var _oauthServer *server.Server

func loginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		//         ctx := context.WithValue(c.Request.Context(), "GinContextKey", c)
		//         c.Request = c.Request.WithContext(ctx)
		LoginHandler(c.Writer, c.Request)
		c.Next()
	}
}

// helper function to setup our server router
func setupRouter() *gin.Engine {
	// Disable Console Color
	// gin.DisableConsoleColor()
	r := gin.Default()

	// GET routes
	r.GET("/apis", ApisHandler)
	r.GET("/oauth/token", TokenHandler)
	r.GET("/kauth", KAuthHandler)

	// POST routes
	r.POST("/kauth", KAuthHandler)
	r.POST("/oauth/authorize", ClientAuthHandler)

	// configure kerberos auth
	if srvConfig.Config.Kerberos.Keytab != "" {
		kt, err := keytab.Load(srvConfig.Config.Kerberos.Keytab)
		if err != nil {
			log.Fatal(err)
		}
		l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
		h := http.HandlerFunc(LoginHandler)
		http.Handle("/", spnego.SPNEGOKRB5Authenticate(h, kt, service.Logger(l)))
	} else {
		r.GET("/", loginHandler())
	}

	// static files
	for _, dir := range []string{"js", "css", "images"} {
		filesFS, err := fs.Sub(StaticFs, "static/"+dir)
		if err != nil {
			panic(err)
		}
		m := fmt.Sprintf("%s/%s", srvConfig.Config.Authz.WebServer.Base, dir)
		r.StaticFS(m, http.FS(filesFS))
	}
	_routes = r.Routes()
	return r
}

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
