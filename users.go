package main

// users module
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//
import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// User represents user table
type User struct {
	ID         uint   `json:"id"`
	LOGIN      string `json:"login"`
	FIRST_NAME string `json:"first_name"`
	LAST_NAME  string `json:"last_name"`
	PASSWORD   string `json:"password"`
	EMAIL      string `json:"email"`
	UPDATED    int64  `json:"updated"`
	CREATED    int64  `json:"created"`
}

// getUser retrieves a user by their login from the database.
func getUser(db *sql.DB, login string) (User, error) {
	var user User
	query := "SELECT id, login, first_name, last_name, password, email, updated, created FROM users WHERE login = ?"
	row := db.QueryRow(query, login)

	err := row.Scan(
		&user.ID,
		&user.LOGIN,
		&user.FIRST_NAME,
		&user.LAST_NAME,
		&user.PASSWORD,
		&user.EMAIL,
		&user.UPDATED,
		&user.CREATED)
	if err == sql.ErrNoRows {
		msg := fmt.Sprintf("User %s is not found", login)
		log.Println("ERROR:", msg)
		return user, errors.New(msg)
	} else if err != nil {
		log.Println("ERROR: failed to query user:", err)
		return user, err
	}

	log.Printf("INFO: query user with login '%s', result %+v", login, user)
	return user, nil
}

// createUser inserts a new user into the database.
func createUser(db *sql.DB, user User) (uint, error) {
	query := `
	INSERT INTO users (login, first_name, last_name, password, email, updated, created)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	now := time.Now().UnixMilli()
	result, err := db.Exec(query, user.LOGIN, user.FIRST_NAME, user.LAST_NAME, user.PASSWORD, user.EMAIL, now, now)
	if err != nil {
		log.Println("ERROR: failed to create user:", err)
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.Println("ERROR: failed to retrieve last insert ID:", err)
		return 0, err
	}

	log.Printf("INFO: created user with ID %d", id)
	return uint(id), nil
}
