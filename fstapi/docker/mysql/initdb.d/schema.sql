CREATE TABLE user (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(128) NOT NULL,
    password_hash VARCHAR(128),
    email VARCHAR(128),
    phone_no VARCHAR(100),
    image_url VARCHAR(128),
    keywords VARCHAR(500),
    PRIMARY KEY (id)
);