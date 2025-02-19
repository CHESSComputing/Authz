CREATE TABLE USERS (
    ID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    LOGIN VARCHAR(700) NOT NULL UNIQUE, -- Too large, will fix in index
    FIRST_NAME VARCHAR(700),
    LAST_NAME VARCHAR(700),
    PASSWORD VARCHAR(700) NOT NULL,
    EMAIL TEXT NOT NULL, -- Cannot be UNIQUE directly
    CREATED INT,
    UPDATED INT,
    UNIQUE INDEX idx_users_login (LOGIN(255)), -- Index only first 255 characters
    UNIQUE INDEX idx_users_email (EMAIL(255))  -- Index only first 255 characters of TEXT
) ENGINE=InnoDB DEFAULT;
