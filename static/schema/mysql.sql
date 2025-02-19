CREATE TABLE USERS (
    ID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    LOGIN VARCHAR(200) NOT NULL UNIQUE,
    FIRST_NAME TEXT,
    LAST_NAME TEXT,
    PASSWORD TEXT NOT NULL,
    EMAIL TEXT NOT NULL,
    CREATE_AT INT,
    UPDATE_AT INT
) ENGINE=InnoDB;
