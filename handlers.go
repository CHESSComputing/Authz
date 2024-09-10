package main

// HTTP handlers module
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//
import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	authz "github.com/CHESSComputing/golib/authz"
	srvConfig "github.com/CHESSComputing/golib/config"
	server "github.com/CHESSComputing/golib/server"
	services "github.com/CHESSComputing/golib/services"
	utils "github.com/CHESSComputing/golib/utils"
	"github.com/gin-gonic/gin"
	oauth2 "github.com/go-oauth2/oauth2/v4"
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
	if kind != "" {
		customClaims.Kind = kind
	}
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
	log.Println("token map", tmap, err)
	if err != nil {
		rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, err)
		c.JSON(http.StatusBadRequest, rec)
		return
	}
	c.JSON(http.StatusOK, tmap)
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
	top := server.TmplPage(StaticFs, "header.tmpl", tmpl)
	bottom := server.TmplPage(StaticFs, "footer.tmpl", tmpl)
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
	// check LDAP group for this user
	if srvConfig.Config.Authz.CheckLDAP {
		entry, err := ldapCache.Search(srvConfig.Config.LDAP.Login, srvConfig.Config.LDAP.Password, rec.User)
		if err != nil {
			msg := fmt.Sprintf("No LDAP entry, error: %v", err)
			rec := services.Response("Authz", http.StatusBadRequest, services.LDAPSearchError, errors.New(msg))
			c.JSON(http.StatusBadRequest, rec)
			return
		}
		group := "" // by default all users will have right access privilege
		if strings.Contains(rec.Scope, "write") {
			group = "foxdenrw" // for write scope user must be in foxdenrw group
		} else if strings.Contains(rec.Scope, "delete") {
			group = "foxdenadmin" // for delete scope user must be in foxdenadmin group
		}
		if group != "" && !entry.Belong(group) {
			msg := fmt.Sprintf("User %s with scope %s is not allowed", rec.User, rec.Scope)
			rec := services.Response("Authz", http.StatusBadRequest, services.LDAPGroupError, errors.New(msg))
			c.JSON(http.StatusBadRequest, rec)
			return
		}
	}

	tmap, err := tokenMap(rec.User, rec.Scope, "kerberos", "Authz")
	log.Println("token map", tmap, err)
	if err != nil {
		rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, err)
		c.JSON(http.StatusBadRequest, rec)
		return
	}
	c.JSON(http.StatusOK, tmap)
}

// TrustedHandler handles request for trusted client
func TrustedHandler(c *gin.Context) {
	r := c.Request
	edata, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, err)
		c.JSON(http.StatusBadRequest, rec)
		return
	}
	var t utils.TrustedClient
	salt := authz.ReadSecret(srvConfig.Config.Encryption.Secret)
	err = t.Decrypt([]byte(edata), salt)
	if err != nil {
		rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, err)
		c.JSON(http.StatusBadRequest, rec)
		return
	}

	// check if user/IP/Mac are matched with our configuration
	var foundIP, foundMAC string
	for _, tuser := range srvConfig.Config.TrustedUsers {
		if tuser.User == t.User {
			for _, ip := range t.IPs {
				if tuser.IP == ip {
					foundIP = ip
					for _, mac := range t.MACs {
						if tuser.MAC == mac.Address {
							foundMAC = mac.Address
						}
					}
				}
			}
		}
	}
	if foundIP == "" || foundMAC == "" {
		log.Printf("ERROR: client %+v not found in trusted list", t)
		rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, errors.New("user not found in trusted list"))
		c.JSON(http.StatusBadRequest, rec)
		return
	}
	clientIP := getIP(r)
	// check if request comes from remote host and skip check for localhost
	if clientIP != "::1" && foundIP != clientIP {
		log.Printf("ERROR: client IP %s does not match with HTTP IP %s", foundIP, clientIP)
		rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, errors.New("client IP does not match with HTTP one"))
		c.JSON(http.StatusBadRequest, rec)
		return
	}

	tmap, err := tokenMap(t.User, "read+write", "trusted_client", "Authz")
	log.Println("token map", tmap, err)
	if err != nil {
		rec := services.Response("Authz", http.StatusBadRequest, services.TokenError, err)
		c.JSON(http.StatusBadRequest, rec)
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
	//     w.WriteHeader(http.StatusFound)

	// get user access token
	tmap, err := tokenMap(name, "read", "kerberos", "Authz")
	log.Println("token map", tmap, err)
	tmpl := server.MakeTmpl(StaticFs, "Login")
	tmpl["Base"] = srvConfig.Config.Authz.WebServer.Base
	header := server.TmplPage(StaticFs, "header.tmpl", tmpl)
	footer := server.TmplPage(StaticFs, "footer.tmpl", tmpl)
	if t, ok := tmap["access_token"]; ok {
		token := fmt.Sprintf("%v", t)
		tmpl["AccessToken"] = token
		claims, err := authz.TokenClaims(token, srvConfig.Config.Authz.ClientID)
		if err != nil {
			log.Println("ERROR", err)
			tmpl["Content"] = err.Error()
			content := server.TmplPage(StaticFs, "error.tmpl", tmpl)
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(header+content+footer))
			return
		}
		data, err := json.MarshalIndent(claims, "", "   ")
		if err == nil {
			tmpl["TokenData"] = string(data)
		} else {
			log.Println("ERROR", err)
		}
		content := server.TmplPage(StaticFs, "token.tmpl", tmpl)
		tmpl["Content"] = template.HTML(content)
	}
	content := server.TmplPage(StaticFs, "success.tmpl", tmpl)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(header+content+footer))
}
