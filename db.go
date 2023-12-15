package main

import (
	"errors"
	"time"

	srvConfig "github.com/CHESSComputing/golib/config"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func initDB(dbKind string) (*gorm.DB, error) {
	var db *gorm.DB
	var err error
	dbConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}
	if srvConfig.Config.Authz.WebServer.Verbose == 0 {
		dbConfig = &gorm.Config{}
	}
	if dbKind == "mysql" {
		// refer https://github.com/go-sql-driver/mysql#dsn-data-source-name for details
		//         dsn := "user:pass@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
		db, err = gorm.Open(mysql.Open(srvConfig.Config.Authz.DBUri), dbConfig)
	} else if dbKind == "sqlite" {
		db, err = gorm.Open(sqlite.Open(srvConfig.Config.Authz.DBUri), dbConfig)
	} else {
		return nil, errors.New("Unsupported database")
	}
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
	sqlDB.SetMaxIdleConns(10)

	// SetMaxOpenConns sets the maximum number of open connections to the database.
	sqlDB.SetMaxOpenConns(100)

	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	sqlDB.SetConnMaxLifetime(time.Hour)
	return db, nil
}
