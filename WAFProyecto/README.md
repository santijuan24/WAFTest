# WAF SIEM Demo Project

Un sistema de demostración completo de Web Application Firewall (WAF) con capacidades SIEM (Security Information and Event Management). Incluye una aplicación web vulnerable intencionalmente para testing de seguridad.

## 🚀 Características

- **WAF Proxy**: Intercepta y analiza tráfico HTTP
- **SIEM Dashboard**: Panel de administración con logs, alertas y estadísticas
- **Aplicación Vulnerable**: Backend con múltiples vulnerabilidades (SQLi, XSS, LFI)
- **Base de Datos**: MySQL con modelos para logs, alertas, IPs bloqueadas
- **Interfaz Web**: Dashboard moderno con configuraciones en tiempo real

## 📋 Requisitos

- Python 3.8+
- MySQL 5.7+ o MariaDB
- Git

## 🛠 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/TU_USUARIO/waf-siem-demo.git
cd waf-siem-demo
```

### 2. Instalar dependencias

```bash
pip install -r waf_project/requirements.txt
pip install -r backend/requirements.txt
```

### 3. Configurar base de datos

#### Crear base de datos MySQL

```sql
CREATE DATABASE waf_security CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

#### Estructura de tablas

El sistema crea automáticamente las siguientes tablas al iniciar:

**request_logs**
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `timestamp` (DATETIME, DEFAULT CURRENT_TIMESTAMP)
- `ip_address` (VARCHAR(45))
- `method` (VARCHAR(10))
- `path` (TEXT)
- `user_agent` (TEXT)
- `risk_score` (FLOAT)
- `action` (ENUM: 'allow', 'block')
- `attack_type` (VARCHAR(100), NULL)
- `rule_hits` (TEXT, NULL)
- `status_code` (INT)
- `log_id` (INT, FOREIGN KEY → alerts.id)

**alerts**
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `timestamp` (DATETIME, DEFAULT CURRENT_TIMESTAMP)
- `level` (ENUM: 'info', 'warning', 'critical')
- `message` (TEXT)
- `source_ip` (VARCHAR(45), NULL)
- `is_read` (BOOLEAN, DEFAULT FALSE)

**blocked_ips**
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `ip_address` (VARCHAR(45), UNIQUE)
- `reason` (TEXT, NULL)
- `blocked_at` (DATETIME, DEFAULT CURRENT_TIMESTAMP)
- `expires_at` (DATETIME, NULL)
- `is_active` (BOOLEAN, DEFAULT TRUE)

**system_config**
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `key` (VARCHAR(100), UNIQUE)
- `value` (TEXT)
- `description` (TEXT, NULL)

**users** (para demo vulnerable)
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `username` (VARCHAR(100), UNIQUE)
- `password` (VARCHAR(255))
- `email` (VARCHAR(255))
- `role` (VARCHAR(50), DEFAULT 'user')
- `created` (TEXT, DEFAULT CURRENT_TIMESTAMP)

**products** (para demo vulnerable)
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `name` (TEXT)
- `price` (REAL)
- `category` (TEXT)
- `stock` (INT, DEFAULT 10)

**orders** (para demo vulnerable)
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `user_id` (INT)
- `product_id` (INT)
- `amount` (INT)
- `total` (REAL)
- `status` (TEXT, DEFAULT 'pending')

### 4. Configurar conexión a BD

Edita `waf_project/config.py`:

```python
DATABASE_URL = "mysql+pymysql://TU_USUARIO:TU_PASSWORD@localhost:3306/waf_security"
```

### 5. Inicializar base de datos

```bash
cd waf_project
python -c "from db_core.connection import init_db; init_db()"
```

Esto crea las tablas y datos de ejemplo.

## 🚀 Ejecutar el sistema

### Opción 1: Todo junto (recomendado)

```bash
# Terminal 1: Backend vulnerable
cd waf_project
python -m uvicorn test_backend.main:app --port 5000 --reload

# Terminal 2: WAF Proxy + Dashboard
cd waf_project
python -m uvicorn waf_proxy.main:app --port 9000 --reload
```

### Opción 2: Componentes separados

```bash
# Backend vulnerable
python -m uvicorn waf_project.test_backend.main:app --port 5000 --reload

# WAF Proxy
python -m uvicorn waf_project.waf_proxy.main:app --port 9000 --reload

# API Admin (opcional, ya incluido en proxy)
python -m uvicorn waf_project.admin_api.main:app --port 8000 --reload
```

## 🎯 Uso

### Dashboard WAF
- URL: `http://localhost:9000/dashboard/`
- Gestiona configuraciones, ve logs/alertas, bloquea IPs

### Aplicación Vulnerable
- URL: `http://localhost:9000/` (a través del proxy)
- URL directa: `http://localhost:5000/` (sin protección)

### Vulnerabilidades de demo

#### SQL Injection
- Login: `' OR 1=1 --`
- Búsqueda: `x' UNION SELECT id,username,password,email,role FROM users --`

#### XSS Reflejado
- Búsqueda: `<script>alert('XSS')</script>`

#### XSS Almacenado
- Comentarios: `<script>alert('Stored XSS')</script>`

#### LFI (Local File Inclusion)
- File reader: `../../../config.py`

## 🔧 Configuración WAF

Desde el dashboard, configura:
- `waf_enabled`: Activar/desactivar WAF
- `score_block_threshold`: Umbral para bloqueo (default: 70)
- `score_warn_threshold`: Umbral para alertas (default: 40)
- `rules_sqli_enabled`: Reglas SQLi
- `rules_xss_enabled`: Reglas XSS
- `rules_lfi_enabled`: Reglas LFI

## 📊 API Endpoints

### Admin API (puerto 9000)
- `GET /api/stats/` - Estadísticas
- `GET /api/logs/` - Logs de requests
- `GET /api/alerts/` - Alertas de seguridad
- `GET /api/config/` - Configuraciones
- `POST /api/config/` - Actualizar config
- `GET /api/blocked-ips/` - IPs bloqueadas
- `POST /api/blocked-ips/` - Bloquear IP
- `DELETE /api/blocked-ips/{ip}` - Desbloquear IP

### Backend Vulnerable (puerto 5000)
- `GET /` - Página principal
- `POST /login/` - Login vulnerable
- `GET /search/` - Búsqueda vulnerable
- `GET /read-file/` - LFI demo
- `GET /comments/` - Comentarios
- `POST /comments/` - Agregar comentario

## 🛡️ Seguridad

⚠️ **Este proyecto es para fines educativos únicamente. NO desplegar en producción.**

- Contiene vulnerabilidades intencionales
- No usar credenciales reales
- Ejecutar en entorno controlado

## 📝 Notas de desarrollo

- El proxy intercepta todo el tráfico al puerto 9000
- Las reglas WAF se aplican en tiempo real
- Los logs se almacenan en BD MySQL
- La UI usa JavaScript vanilla, sin frameworks

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agrega nueva funcionalidad'`)
4. Push (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto es open source bajo la licencia MIT.