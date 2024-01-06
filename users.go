package main

// users module
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//
import (
	"errors"
	"fmt"
	"log"

	srvConfig "github.com/CHESSComputing/golib/config"
	"gorm.io/gorm"
)

// User represents user table
type User struct {
	ID         uint   `json:"id" gorm:"unsigned;primaryKey;autoIncrement:true,unique"`
	LOGIN      string `json:"login"`
	FIRST_NAME string `json:"first_name"`
	LAST_NAME  string `json:"last_name"`
	PASSWORD   string `json:"password"`
	EMAIL      string `json:"email"`
	UPDATED    int64  `json:"updated" gorm:"autoUpdateTime:milli"` // Use unix milli seconds as updating time
	CREATED    int64  `json:"created" gorm:"autoCreateTime"`       // Use unix seconds as creating time
}

func getUser(db *gorm.DB, user User) (User, error) {
	// Get first matched record
	// SELECT * FROM users WHERE Login = ...
	var u User
	cond := fmt.Sprintf("LOGIN = ?")
	result := db.Where(cond, user.LOGIN).First(&u)
	//     result := db.First(&u, cond, user.Login)
	if result.RowsAffected == 0 {
		msg := fmt.Sprintf("User %s is not found", user.LOGIN)
		log.Println("ERROR:", msg)
		return u, errors.New(msg)
	}
	if srvConfig.Config.Authz.WebServer.Verbose > 0 {
		log.Printf("INFO: query user %+v, result %+v, found %+v", user, result, u)
	}
	return u, nil
}

func createUser(db *gorm.DB, user User) (uint, error) {
	result := db.Create(&user) // pass pointer of data to Create
	return user.ID, result.Error
}
