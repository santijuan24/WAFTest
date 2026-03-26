"""
WAF Project – Configuración central
Variables de entorno para despliegue en AWS.
"""

import os

# ── Base de datos MySQL (sentinel_waf) ────────────────────────────────────────
DB_HOST     = os.environ.get("DB_HOST", "localhost")
DB_PORT     = int(os.environ.get("DB_PORT", "3306"))
DB_USER     = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME     = os.environ.get("DB_NAME", "sentinel_waf")

DATABASE_URL = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    "?charset=utf8mb4"
)

# ── Puertos de los servicios ──────────────────────────────────────────────────
WAF_PROXY_PORT   = int(os.environ.get("WAF_PROXY_PORT", "8080"))
API_PORT         = int(os.environ.get("API_PORT", "8000"))
BACKEND_PORT     = int(os.environ.get("BACKEND_PORT", "3000"))

# ── URLs de los servicios ─────────────────────────────────────────────────────
BACKEND_URL      = os.environ.get("BACKEND_URL", f"http://localhost:{BACKEND_PORT}")

# ── Control del WAF ──────────────────────────────────────────────────────────
import tempfile

def get_waf_flag_path():
    # Usamos el directorio temporal del sistema operativo (/tmp en Linux) 
    # para evitar PermissionError (error 500) cuando la carpeta de AWS 
    # es modificada remotamente por root.
    return os.path.join(tempfile.gettempdir(), ".sentinel_waf_disabled")

def is_waf_enabled() -> bool:
    flag_file = get_waf_flag_path()
    if os.path.exists(flag_file):
        return False
    return os.environ.get("WAF_ENABLED", "true").lower() == "true"

def set_waf_enabled(enabled: bool):
    flag_file = get_waf_flag_path()
    if enabled and os.path.exists(flag_file):
        try:
            os.remove(flag_file)
        except OSError:
            pass
    elif not enabled and not os.path.exists(flag_file):
        try:
            open(flag_file, 'a').close()
        except OSError:
            pass


# ── Umbrales de riesgo (alineados con fn_evaluar_criticidad) ─────────────────
SCORE_ALLOW = 40    # score < 40  → Permitida
SCORE_WARN  = 70    # 40 ≤ score < 70 → Alerta / Advertencia
                    # score ≥ 70      → Bloqueada / Critico

# ── Directorio de reglas de detección ────────────────────────────────────────
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# ── Mapeo: categoría de regla → id_ataque en tabla tipos_ataque ──────────────
# Estos IDs corresponden a los INSERT del script create_database.sql
ATTACK_TYPE_MAP = {
    "SQL Injection": 1,                              # SQLi
    "Cross-Site Scripting (XSS)": 2,                  # XSS
    "Local File Inclusion (LFI) / Path Traversal": 3,  # LFI
}
