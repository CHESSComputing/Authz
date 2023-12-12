--------------------------------------------------------
--  DDL for Table USER
--------------------------------------------------------

CREATE TABLE "USERS" (
    "ID" INTEGER PRIMARY KEY,
    "LOGIN" VARCHAR2(700) NOT NULL UNIQUE,
    "FIRST_NAME" VARCHAR2(700),
    "LAST_NAME" VARCHAR2(700),
    "PASSWORD" VARCHAR2(700) NOT NULL,
    "EMAIL" TEXT NOT NULL UNIQUE,
    "CREATED" INTEGER,
    "UPDATED" INTEGER
);
