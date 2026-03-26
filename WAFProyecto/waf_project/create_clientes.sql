-- Script para añadir la tabla de 'clientes' requerida por Sentinel Agent SDK
USE sentinel_waf;

CREATE TABLE IF NOT EXISTS clientes (
    client_id VARCHAR(50) PRIMARY KEY,
    api_key VARCHAR(100) NOT NULL UNIQUE,
    nombre_empresa VARCHAR(150) NOT NULL,
    target_url VARCHAR(255) DEFAULT NULL,
    plan VARCHAR(50) DEFAULT 'basico',
    activo BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insertar un cliente de prueba (Demo Client)
INSERT INTO clientes (client_id, api_key, nombre_empresa, target_url, plan)
VALUES (
    'demo-client-id-001',
    'sk_test_sentinel_123456789',
    'Escuela Demo SA de CV',
    'http://localhost:3000',
    'enterprise'
) ON DUPLICATE KEY UPDATE activo=1;
