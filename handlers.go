package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	authz "github.com/CHESSComputing/golib/authz"
	srvConfig "github.com/CHESSComputing/golib/config"
	server "github.com/CHESSComputing/golib/server"
	services "github.com/CHESSComputing/golib/services"
	"github.com/gin-gonic/gin"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-session/session"
	credentials "gopkg.in/jcmturner/gokrb5.v7/credentials"
)

type DocsParams struct {
	Login string `json:"login" uri:"login" binding:"required"`
}
type UserParams struct {
	Login    string `json:"login" uri:"login" binding:"required"`
	Password string `json:"password" uri:"password" binding:"required"`
}

// content is our static web server content.
//
//go:embed static
var StaticFs embed.FS

// helper function to handle http server errors
func handleError(c *gin.Context, msg string, err error) {
	w := c.Writer
	log.Printf("ERROR: %v\n", err)
	tmpl := server.MakeTmpl(StaticFs, "Error")
	tmpl["Message"] = strings.ToTitle(msg)
	page := server.TmplPage(StaticFs, "error.tmpl", tmpl)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(page))
}

// helper function to get valid token
func validToken(c *gin.Context, user, scope string) (oauth2.GrantType, *oauth2.TokenGenerateRequest, error) {
	var gt oauth2.GrantType
	// for grant type we must use AuthorizationCode which force creation of access token with valid scope
	//     gt = oauth2.AuthorizationCode
	gt = oauth2.ClientCredentials
	//     gt = oauth2.PasswordCredentials
	duration := srvConfig.Config.Authz.TokenExpires
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:       srvConfig.Config.Authz.ClientID,
		ClientSecret:   srvConfig.Config.Authz.ClientSecret,
		UserID:         user,
		Scope:          scope,
		AccessTokenExp: time.Duration(duration),
		Request:        c.Request,
	}
	return gt, tgr, nil
}

// helper function to generate valid token map
func tokenMap(user, scope, kind, app string) (map[string]any, error) {
	tmap := make(map[string]any)
	customClaims := authz.CustomClaims{User: user, Scope: scope, Kind: "client_credentials", Application: "Authz"}
	duration := srvConfig.Config.Authz.TokenExpires
	if duration == 0 {
		duration = 7200
	}
	accessToken, err := authz.JWTAccessToken(
		srvConfig.Config.Authz.ClientID, duration, customClaims)
	if err != nil {
		return tmap, err
	}
	tmap["access_token"] = accessToken
	tmap["scope"] = scope
	tmap["token_type"] = "Bearer"
	tmap["expires_at"] = duration
	return tmap, nil
}

// TokenHandler provides access to GET /oauth/token end-point
func TokenHandler(c *gin.Context) {

	r := c.Request
	scope := r.URL.Query().Get("scope")
	user := r.URL.Query().Get("user")
	tmap, err := tokenMap(user, scope, "client_credentials", "Authz")
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}
	c.JSON(http.StatusOK, tmap)

	/*
		// here is the same logic of _oauthServer.HandleTokenRequest
		// TODO: we may change token attributes as expires, scope, etc.
		// we expect to receive: oauth2.GrantType, *oauth2.TokenGenerateRequest, error
		grantType, tokenGenRequest, err := _oauthServer.ValidationTokenRequest(c.Request)
		if err != nil {
			log.Println("ERROR: oauth server error", err)
			http.Error(c.Writer, err.Error(), http.StatusBadRequest)
		}
		if user != "" {
			tokenGenRequest.UserID = user
		}
		if scope != "" {
			tokenGenRequest.Scope = scope
		}

		log.Printf("grantType %+v tokenGenRequest %+v", grantType, tokenGenRequest)

		tokenInfo, err := _oauthServer.GetAccessToken(c, grantType, tokenGenRequest)
		if err != nil {
			log.Println("ERROR: oauth server error", err)
			http.Error(c.Writer, err.Error(), http.StatusBadRequest)
		}

		// set custom token attributes
		duration := srvConfig.Config.Authz.TokenExpires
		if duration > 0 {
			tokenInfo.SetCodeExpiresIn(time.Duration(duration))
		}
		data := _oauthServer.GetTokenData(tokenInfo)

		// encode given token token data back to http response writer
		enc := json.NewEncoder(c.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(data)
	*/
}

// AuthzHandler provides access to POST /oauth/authorize end-point
func AuthzHandler(c *gin.Context) {
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}
	var params UserParams
	if err := c.BindJSON(&params); err == nil {
		user := User{
			LOGIN:    params.Login,
			PASSWORD: params.Password,
		}
		if u, err := getUser(_DB, user); err == nil {
			store.Set("UserID", u.ID)
			store.Save()

			err = _oauthServer.HandleAuthorizeRequest(c.Writer, c.Request)
			if err != nil {
				log.Println("ERROR: oauth server error", err)
				http.Error(c.Writer, err.Error(), http.StatusBadRequest)
			}
			c.Writer.Header().Set("Location", "/oauth2/authorize")
			if srvConfig.Config.Authz.WebServer.Verbose > 0 {
				log.Println("INFO: found user", u)
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok", "uid": u.ID})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "error": err.Error()})
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "error": err.Error()})
	}
}

// LoginHandler handlers Login requests
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// func LoginHandler(c *gin.Context) {
	//     w := c.Writer
	//     r := c.Request
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tmpl := server.MakeTmpl(StaticFs, "Login")
	tmpl["Title"] = "Login"
	tmpl["Base"] = srvConfig.Config.Frontend.WebServer.Base
	tmpl["ServerInfo"] = srvConfig.Info()
	top := server.TmplPage(StaticFs, "top.tmpl", tmpl)
	bottom := server.TmplPage(StaticFs, "bottom.tmpl", tmpl)
	tmpl["StartTime"] = time.Now().Unix()
	page := server.TmplPage(StaticFs, "login.tmpl", tmpl)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(top + page + bottom))
}

// ClientAuthHandler provides kerberos authentication for CLI requests
// func ClientAuthHandler(w http.ResponseWriter, r *http.Request) {
func ClientAuthHandler(c *gin.Context) {
	r := c.Request

	var rec authz.Kerberos
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		rec := services.Response("Authz", http.StatusBadRequest, services.ReaderError, err)
		c.JSON(http.StatusBadRequest, rec)
		return
	}
	err = json.Unmarshal(data, &rec)
	if err != nil {
		rec := services.Response("Authz", http.StatusBadRequest, services.UnmarshalError, err)
		c.JSON(http.StatusBadRequest, rec)
		return
	}
	creds, err := rec.Credentials()
	if err != nil || creds.Expired() {
		rec := services.Response("Authz", http.StatusBadRequest, services.CredentialsError, err)
		c.JSON(http.StatusBadRequest, rec)
		return
	}
	if creds.Expired() {
		rec := services.Response("Authz", http.StatusBadRequest, services.CredentialsError, errors.New("Expired token"))
		c.JSON(http.StatusBadRequest, rec)
		return
	}
	if creds.UserName() != rec.User {
		rec := services.Response("Authz", http.StatusBadRequest, services.CredentialsError, errors.New("User credentials error"))
		c.JSON(http.StatusBadRequest, rec)
		return
	}

	/*
		// generate in response valid token
		grantType, tokenGenRequest, err := validToken(c, rec.User, rec.Scope)
		//     grantType, tokenGenRequest, err := _oauthServer.ValidationTokenRequest(c.Request)
		if err != nil {
			rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, err)
			c.JSON(http.StatusBadRequest, rec)
			return
		}
		// add token attributes
		log.Printf("grantType %+v tokenGenRequest %+v", grantType, tokenGenRequest)
		tokenInfo, err := _oauthServer.GetAccessToken(c, grantType, tokenGenRequest)
		if err != nil {
			rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, err)
			c.JSON(http.StatusBadRequest, rec)
			return
		}
		// set custom token attributes
		duration := srvConfig.Config.Authz.TokenExpires
		if duration > 0 {
			tokenInfo.SetCodeExpiresIn(time.Duration(duration))
		}
		if rec.Scope != "" {
			tokenInfo.SetScope(rec.Scope)
		}
		tmap := _oauthServer.GetTokenData(tokenInfo)
	*/

	tmap, err := tokenMap(rec.User, rec.Scope, "kerberos", "Authz")
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}
	c.JSON(http.StatusOK, tmap)
}

// KAuthHandler provides KAuth authentication to our app
// func KAuthHandler(w http.ResponseWriter, r *http.Request) {
func KAuthHandler(c *gin.Context) {
	// get http request/writer
	w := c.Writer
	r := c.Request

	/*
		// if in test mode or do not use keytab
		if srvConfig.Config.Kerberos.Keytab == "" || srvConfig.Config.Authz.TestMode {
			// TODO: get user from cookie
			user := "bla"
			gt, treq, err := validToken(c, user, "read")
			if err != nil {
				msg := "wrong user credentials"
				handleError(c, msg, err)
				return
			}
			tokenInfo, err := _oauthServer.GetAccessToken(c, gt, treq)
			if err != nil {
				msg := "wrong access token"
				handleError(c, msg, err)
				return
			}
			// set custom token attributes
			duration := srvConfig.Config.Authz.TokenExpires
			if duration > 0 {
				tokenInfo.SetCodeExpiresIn(time.Duration(duration))
			}
			tmap := _oauthServer.GetTokenData(tokenInfo)
			data, err := json.MarshalIndent(tmap, "", "  ")
			if err != nil {
				msg := "fail to marshal token map"
				handleError(c, msg, err)
				return
			}

			tmpl := server.MakeTmpl(StaticFs, "Success")
			tmpl["Content"] = fmt.Sprintf("<br/>Generated token:<br/><pre>%s</pre>", string(data))
			page := server.TmplPage(StaticFs, "success.tmpl", tmpl)
			top := server.TmplPage(StaticFs, "top.tmpl", tmpl)
			bottom := server.TmplPage(StaticFs, "bottom.tmpl", tmpl)
			w.Write([]byte(top + page + bottom))
			return
		}
	*/

	// First, we need to get the value of the `code` query param
	err := r.ParseForm()
	if err != nil {
		log.Printf("could not parse http form, error %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
	}
	name := r.FormValue("name")
	password := r.FormValue("password")
	var creds *credentials.Credentials
	if name != "" && password != "" {
		creds, err = kuser(name, password)
		if err != nil {
			msg := "wrong user credentials"
			handleError(c, msg, err)
			return
		}
	} else {
		msg := "user/password is empty"
		handleError(c, msg, err)
		return
	}
	if creds == nil {
		msg := "unable to obtain user credentials"
		handleError(c, msg, err)
		return
	}

	expiration := time.Now().Add(24 * time.Hour)
	msg := fmt.Sprintf("%s-%v", creds.UserName(), creds.Authenticated())
	//     byteArray := encrypt([]byte(msg), Config.StoreSecret)
	//     n := bytes.IndexByte(byteArray, 0)
	//     s := string(byteArray[:n])
	cookie := http.Cookie{Name: "auth-session", Value: msg, Expires: expiration}
	http.SetCookie(w, &cookie)

	w.WriteHeader(http.StatusFound)
}
