-- ============================================================
--  WAF Project – Base de datos MySQL para XAMPP
--  Ejecutar este script una sola vez en phpMyAdmin o MySQL CLI
-- ============================================================

CREATE DATABASE IF NOT EXISTS waf_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE waf_db;

-- ── Tabla de logs de peticiones ──────────────────────────────
CREATE TABLE IF NOT EXISTS request_logs (
    id          INT          NOT NULL AUTO_INCREMENT,
    timestamp   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address  VARCHAR(45)  NOT NULL,
    method      VARCHAR(10)  NOT NULL,
    path        VARCHAR(2048) NOT NULL,
    user_agent  VARCHAR(512) NULL,
    risk_score  FLOAT        NOT NULL DEFAULT 0.0,
    action      VARCHAR(20)  NOT NULL DEFAULT 'allow',   -- allow / block
    attack_type VARCHAR(100) NULL,                       -- sqli, xss, lfi …
    rule_hits   TEXT         NULL,                       -- JSON list of rule ids
    status_code INT          NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Tabla de IPs bloqueadas ───────────────────────────────────
CREATE TABLE IF NOT EXISTS blocked_ips (
    id          INT          NOT NULL AUTO_INCREMENT,
    ip_address  VARCHAR(45)  NOT NULL UNIQUE,
    reason      VARCHAR(512) NULL,
    blocked_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME     NULL,          -- NULL = bloqueo permanente
    is_active   TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Tabla de alertas de seguridad ────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id          INT          NOT NULL AUTO_INCREMENT,
    timestamp   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    level       VARCHAR(20)  NOT NULL,      -- info / warning / critical
    message     TEXT         NOT NULL,
    source_ip   VARCHAR(45)  NULL,
    log_id      INT          NULL,
    is_read     TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT fk_alerts_log
        FOREIGN KEY (log_id) REFERENCES request_logs(id)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Tabla de configuración del sistema ───────────────────────
CREATE TABLE IF NOT EXISTS system_config (
    id          INT          NOT NULL AUTO_INCREMENT,
    `key`       VARCHAR(100) NOT NULL UNIQUE,
    value       TEXT         NULL,
    description VARCHAR(512) NULL,
    updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Datos iniciales de configuración ─────────────────────────
INSERT IGNORE INTO system_config (`key`, value, description) VALUES
    ('waf_enabled',           'true', 'Habilitar / deshabilitar la interceptación del WAF'),
    ('score_block_threshold', '70',   'Puntuación de riesgo >= este valor → BLOQUEAR'),
    ('score_warn_threshold',  '40',   'Puntuación de riesgo >= este valor → AVISO'),
    ('rules_sqli_enabled',    'true', 'Reglas de inyección SQL activas'),
    ('rules_xss_enabled',     'true', 'Reglas XSS activas'),
    ('rules_lfi_enabled',     'true', 'Reglas de LFI / recorrido de rutas activas'),
    ('auto_block_on_attack',  'true', 'Bloquear IP automáticamente tras ataque confirmado');

-- ── Verificación ─────────────────────────────────────────────
SELECT 'Base de datos waf_db creada correctamente.' AS resultado;
SHOW TABLES;
