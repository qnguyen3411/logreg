CREATE TABLE IF NOT EXISTS users(
id INT(11) NOT NULL AUTO_INCREMENT,
first_name VARCHAR(45) NOT NULL,
last_name VARCHAR(45) NOT NULL,
email VARCHAR(45) NOT NULL,
password VARCHAR(255) NOT NULL,
PRIMARY KEY(id)
)
;

CREATE TABLE messages(
    id INT(11) NOT NULL AUTO_INCREMENT,
    content TEXT NOT NULL,
    sender_id INT(11) NOT NULL,
    receiver_id INT(11) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id)
)