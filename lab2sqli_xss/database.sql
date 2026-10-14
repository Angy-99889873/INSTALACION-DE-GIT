-- ============================================================
-- LABORATORIO 2 – INYECCIÓN SQL (SQLi), XSS Y DEFENSAS WEB
-- GSR600 – Seguridad Informática
-- Archivo: database.sql
-- Replicación del esquema y registros oficiales de DVWA
-- ============================================================

CREATE DATABASE IF NOT EXISTS `gsr600`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `gsr600`;

-- ------------------------------------------------------------
-- TABLA: users (Esquema estándar DVWA utilizado en la guía)
-- ------------------------------------------------------------
DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
    `user_id`       INT(6) NOT NULL AUTO_INCREMENT,
    `first_name`    VARCHAR(15) NOT NULL,
    `last_name`     VARCHAR(15) NOT NULL,
    `user`          VARCHAR(15) NOT NULL,
    `password`      VARCHAR(32) NOT NULL,
    `avatar`        VARCHAR(70) DEFAULT NULL,
    `last_login`    TIMESTAMP NULL DEFAULT NULL,
    `failed_login`  INT(3) DEFAULT 0,
    PRIMARY KEY (`user_id`),
    UNIQUE KEY `uq_user` (`user`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- REGISTROS OFICIALES DE LA GUÍA (Hashes MD5 de DVWA)
-- ============================================================
-- 1. admin   → password → 5f4dcc3b5aa765d61d8327deb882cf99
-- 2. gordonb → abc123   → e99a18c428cb38d5f260853678922e03
-- 3. 1337    → charley  → 8d3533d75ae2c3966d7e0d4fcc69216b
-- 4. pablo   → letmein  → 0d107d09f5bbe40cade3de5c71e9e9b7
-- 5. smithy  → password → 5f4dcc3b5aa765d61d8327deb882cf99
-- ============================================================

INSERT INTO `users` (`user_id`, `first_name`, `last_name`, `user`, `password`, `avatar`, `last_login`, `failed_login`) VALUES
(1, 'admin', 'admin', 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'images/admin.jpg', NOW(), 0),
(2, 'Gordon', 'Brown', 'gordonb', 'e99a18c428cb38d5f260853678922e03', 'images/gordonb.jpg', NOW() - INTERVAL 1 DAY, 0),
(3, 'Hack', 'Me', '1337', '8d3533d75ae2c3966d7e0d4fcc69216b', 'images/1337.jpg', NOW() - INTERVAL 2 DAY, 0),
(4, 'Pablo', 'Picasso', 'pablo', '0d107d09f5bbe40cade3de5c71e9e9b7', 'images/pablo.jpg', NOW() - INTERVAL 3 DAY, 0),
(5, 'Bob', 'Smith', 'smithy', '5f4dcc3b5aa765d61d8327deb882cf99', 'images/smithy.jpg', NOW() - INTERVAL 4 DAY, 0);
