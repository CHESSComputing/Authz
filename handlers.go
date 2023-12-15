package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	srvConfig "github.com/CHESSComputing/golib/config"
	utils "github.com/CHESSComputing/golib/utils"
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

// helper function to make initial template struct
func makeTmpl(c *gin.Context, title string) utils.TmplRecord {
	tmpl := make(utils.TmplRecord)
	tmpl["Title"] = title
	tmpl["User"] = ""
	if user, ok := c.Get("user"); ok {
		tmpl["User"] = user
	}
	tmpl["Base"] = srvConfig.Config.Frontend.WebServer.Base
	tmpl["ServerInfo"] = srvConfig.Info()
	tmpl["Top"] = utils.TmplPage(StaticFs, "top.tmpl", tmpl)
	tmpl["Bottom"] = utils.TmplPage(StaticFs, "bottom.tmpl", tmpl)
	tmpl["StartTime"] = time.Now().Unix()
	return tmpl
}

// helper function to handle http server errors
func handleError(c *gin.Context, msg string, err error) {
	w := c.Writer
	log.Printf("ERROR: %v\n", err)
	tmpl := makeTmpl(c, "Error")
	tmpl["Message"] = strings.ToTitle(msg)
	page := utils.TmplPage(StaticFs, "error.tmpl", tmpl)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(page))
}

// UsersHandler provides access to GET /sites end-point
func UsersHandler(c *gin.Context) {
	var params DocsParams
	if err := c.ShouldBindUri(&params); err == nil {
		user := User{
			LOGIN: params.Login,
		}
		if u, err := getUser(_DB, user); err == nil {
			c.JSON(200, gin.H{"status": "ok", "user": u})
		} else {
			c.JSON(400, gin.H{"status": "fail", "error": err.Error()})
		}
	} else {
		c.JSON(400, gin.H{"status": "fail", "error": err.Error()})
	}
}

// UserRequest represents user form request
type UserRequest struct {
	Login     string `json:"login"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password"`
	Email     string `json:"email"`
}

// RegistryUserHandler provides access to POST /user end-point
func RegistryUserHandler(c *gin.Context) {
	var form UserRequest
	err := c.BindJSON(&form)
	if err == nil {
		// create new user in DB
		user := User{
			LOGIN:      form.Login,
			FIRST_NAME: form.FirstName,
			LAST_NAME:  form.LastName,
			PASSWORD:   form.Password,
			EMAIL:      form.Email,
		}
		uid, err := createUser(_DB, user)
		if err != nil {
			c.JSON(400, gin.H{"status": "fail", "error": err.Error()})
		} else {
			c.JSON(200, gin.H{"status": "ok", "uid": uid})
		}
	} else {
		c.JSON(400, gin.H{"status": "fail", "error": err.Error()})
	}
}

// helper function to validate user and generate token
func validateUser(c *gin.Context) (oauth2.GrantType, *oauth2.TokenGenerateRequest, error) {
	var gt oauth2.GrantType
	gt = "client_credentials"
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     srvConfig.Config.Authz.ClientID,
		ClientSecret: srvConfig.Config.Authz.ClientSecret,
		Request:      c.Request,
	}
	return gt, tgr, nil
}

// TokenHandler provides access to GET /oauth/token end-point
func TokenHandler(c *gin.Context) {
	/*
		err := _oauthServer.HandleTokenRequest(c.Writer, c.Request)
		if err != nil {
			log.Println("ERROR: oauth server error", err)
			http.Error(c.Writer, err.Error(), http.StatusBadRequest)
		}
	*/

	// here is the same logic of _oauthServer.HandleTokenRequest
	// TODO: we may change token attributes as expires, scope, etc.
	// we expect to receive: oauth2.GrantType, *oauth2.TokenGenerateRequest, error
	grantType, tokenGenRequest, err := _oauthServer.ValidationTokenRequest(c.Request)
	if err != nil {
		log.Println("ERROR: oauth server error", err)
		http.Error(c.Writer, err.Error(), http.StatusBadRequest)
	}
	log.Printf("grantType %+v tokenGenRequest %+v", grantType, tokenGenRequest)

	tokenInfo, err := _oauthServer.GetAccessToken(c, grantType, tokenGenRequest)
	if err != nil {
		log.Println("ERROR: oauth server error", err)
		http.Error(c.Writer, err.Error(), http.StatusBadRequest)
	}
	/*
		// set userID
		r := c.Request
		cookie, err := r.Cookie("auth-session")
		// TODO: data is map[string]interface{}
		if err == nil {
			// our cookie is set as following
			//     msg := fmt.Sprintf("%s-%v", creds.UserName(), creds.Authenticated())
			//     cookie := http.Cookie{Name: "auth-session", Value: msg, Expires: expiration}
			//     http.SetCookie(w, &cookie)
			value := cookie.Value
			arr := strings.Split(value, "-")
			tokenInfo.SetUserID(arr[0])
		}
	*/

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
			c.JSON(200, gin.H{"status": "ok", "uid": u.ID})
		} else {
			c.JSON(400, gin.H{"status": "fail", "error": err.Error()})
		}
	} else {
		c.JSON(400, gin.H{"status": "fail", "error": err.Error()})
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
	//     tmpl := makeTmpl(c, "Login")
	tmpl := make(utils.TmplRecord)
	tmpl["Title"] = "Login"
	tmpl["Base"] = srvConfig.Config.Frontend.WebServer.Base
	tmpl["ServerInfo"] = srvConfig.Info()
	top := utils.TmplPage(StaticFs, "top.tmpl", tmpl)
	bottom := utils.TmplPage(StaticFs, "bottom.tmpl", tmpl)
	tmpl["StartTime"] = time.Now().Unix()
	page := utils.TmplPage(StaticFs, "login.tmpl", tmpl)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(top + page + bottom))
}

// KAuthHandler provides KAuth authentication to our app
// func KAuthHandler(w http.ResponseWriter, r *http.Request) {
func KAuthHandler(c *gin.Context) {
	// get http request/writer
	w := c.Writer
	r := c.Request

	// if in test mode or do not use keytab
	if srvConfig.Config.Kerberos.Keytab == "" || srvConfig.Config.Authz.TestMode {
		gt, treq, err := validateUser(c)
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

		tmpl := makeTmpl(c, "Success")
		tmpl["Content"] = fmt.Sprintf("<br/>Generated token:<br/><pre>%s</pre>", string(data))
		page := utils.TmplPage(StaticFs, "success.tmpl", tmpl)
		top := utils.TmplPage(StaticFs, "top.tmpl", tmpl)
		bottom := utils.TmplPage(StaticFs, "bottom.tmpl", tmpl)
		w.Write([]byte(top + page + bottom))
		return
	}

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

	// TODO: I need to generate valid token
	//     w.Header().Set("Location", "/data")
	w.WriteHeader(http.StatusFound)
}
