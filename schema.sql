CREATE DATABASE IF NOT EXISTS whois_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE whois_db;

CREATE TABLE IF NOT EXISTS query_log (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_ip   VARCHAR(45)  NOT NULL,          -- IPv4 или IPv6
    domain_name VARCHAR(253) NOT NULL,           -- максимальная длина домена
    queried_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    registrar   VARCHAR(100) DEFAULT NULL,       -- какой регистратор ответил
    status      ENUM('success','error') NOT NULL DEFAULT 'success',
    INDEX idx_domain (domain_name),
    INDEX idx_time   (queried_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
