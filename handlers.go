package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	srvConfig "github.com/CHESSComputing/common/config"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session"
)

type DocsParams struct {
	Login string `json:"login" uri:"login" binding:"required"`
}
type UserParams struct {
	Login    string `json:"login" uri:"login" binding:"required"`
	Password string `json:"password" uri:"password" binding:"required"`
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
	grantType, tokenGenRequest, err := _oauthServer.ValidationTokenRequest(c.Request)
	if err != nil {
		log.Println("ERROR: oauth server error", err)
		http.Error(c.Writer, err.Error(), http.StatusBadRequest)
	}

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
