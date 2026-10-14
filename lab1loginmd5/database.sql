-- ============================================================
-- LABORATORIO 1 – LOGIN VULNERABLE CON MD5
-- GSR600 – Seguridad Informática
-- ============================================================
-- ADVERTENCIA: Este script crea datos ficticios para uso
-- exclusivamente educativo en entorno local controlado.
-- NO utilizar en producción. NO publicar en Internet.
-- ============================================================

CREATE DATABASE IF NOT EXISTS `gsr600`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `gsr600`;

-- ------------------------------------------------------------
-- TABLA: usuarios
-- ------------------------------------------------------------
DROP TABLE IF EXISTS `password_resets`;
DROP TABLE IF EXISTS `usuarios`;

CREATE TABLE `usuarios` (
    `id`              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `nombres`         VARCHAR(100) NOT NULL,
    `apellidos`       VARCHAR(100) NOT NULL,
    `usuario`         VARCHAR(50)  NOT NULL,
    `email`           VARCHAR(150) NOT NULL,
    `telefono`        VARCHAR(20)  DEFAULT NULL,
    `password`        VARCHAR(255) NOT NULL COMMENT 'LAB1: MD5 sin salt – intencionalmente vulnerable',
    `rol`             ENUM('admin','docente','estudiante','invitado') NOT NULL DEFAULT 'estudiante',
    `estado`          TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1=activo, 0=inactivo',
    `fecha_registro`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `ultimo_login`    DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_usuario` (`usuario`),
    UNIQUE KEY `uq_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Laboratorio 1 – contraseñas hasheadas con MD5 sin salt';

-- ------------------------------------------------------------
-- TABLA: password_resets
-- ------------------------------------------------------------
CREATE TABLE `password_resets` (
    `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `email`      VARCHAR(150) NOT NULL,
    `token`      VARCHAR(64)  NOT NULL,
    `expires_at` DATETIME NOT NULL,
    `used`       TINYINT(1) NOT NULL DEFAULT 0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_token` (`token`),
    KEY `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- USUARIOS DE LABORATORIO (contraseñas ficticias – MD5)
-- ============================================================
-- admin        → 123456      → MD5: e10adc3949ba59abbe56e057f20f883e
-- docente      → password    → MD5: 5f4dcc3b5aa765d61d8327deb882cf99
-- estudiante1  → admin123    → MD5: 0192023a7bbd73250516f069df18b500
-- estudiante2  → 123456      → MD5: e10adc3949ba59abbe56e057f20f883e  (igual que admin)
-- estudiante3  → 12345678    → MD5: 25d55ad283aa400af464c76d713c07ad
-- estudiante4  → qwerty      → MD5: d8578edf8458ce06fbc5bb76a58c5ca4
-- invitado     → invitado    → MD5: 9db2c10e0cdad4ab0b87adf2fc69a35b
-- ============================================================

INSERT INTO `usuarios`
    (`nombres`, `apellidos`, `usuario`, `email`, `telefono`, `password`, `rol`, `estado`, `fecha_registro`)
VALUES
-- md5('123456') = e10adc3949ba59abbe56e057f20f883e
('Administrador', 'Sistema', 'admin',
 'admin@lab.local', '555-0001',
 'e10adc3949ba59abbe56e057f20f883e', 'admin', 1,
 NOW() - INTERVAL 30 DAY),

-- md5('password') = 5f4dcc3b5aa765d61d8327deb882cf99
('Carlos', 'Docente', 'docente',
 'docente@lab.local', '555-0002',
 '5f4dcc3b5aa765d61d8327deb882cf99', 'docente', 1,
 NOW() - INTERVAL 20 DAY),

-- md5('admin123') = 0192023a7bbd73250516f069df18b500
('María', 'García López', 'estudiante1',
 'estudiante1@lab.local', '555-0003',
 '0192023a7bbd73250516f069df18b500', 'estudiante', 1,
 NOW() - INTERVAL 15 DAY),

-- md5('123456') = e10adc3949ba59abbe56e057f20f883e  ← MISMO HASH que admin
('Juan', 'Martínez Ruiz', 'estudiante2',
 'estudiante2@lab.local', '555-0004',
 'e10adc3949ba59abbe56e057f20f883e', 'estudiante', 1,
 NOW() - INTERVAL 15 DAY),

-- md5('12345678') = 25d55ad283aa400af464c76d713c07ad
('Ana', 'Pérez Soto', 'estudiante3',
 'estudiante3@lab.local', '555-0005',
 '25d55ad283aa400af464c76d713c07ad', 'estudiante', 1,
 NOW() - INTERVAL 10 DAY),

-- md5('qwerty') = d8578edf8458ce06fbc5bb76a58c5ca4
('Luis', 'Rodríguez Vega', 'estudiante4',
 'estudiante4@lab.local', '555-0006',
 'd8578edf8458ce06fbc5bb76a58c5ca4', 'estudiante', 0,
 NOW() - INTERVAL 5 DAY),

-- md5('invitado') = 9db2c10e0cdad4ab0b87adf2fc69a35b
('Usuario', 'Invitado', 'invitado',
 'invitado@lab.local', NULL,
 '9db2c10e0cdad4ab0b87adf2fc69a35b', 'invitado', 1,
 NOW());

-- Simular último login para algunos usuarios
UPDATE `usuarios` SET `ultimo_login` = NOW() - INTERVAL 2 DAY  WHERE `usuario` = 'admin';
UPDATE `usuarios` SET `ultimo_login` = NOW() - INTERVAL 1 DAY  WHERE `usuario` = 'docente';
UPDATE `usuarios` SET `ultimo_login` = NOW() - INTERVAL 3 HOUR WHERE `usuario` = 'estudiante1';
