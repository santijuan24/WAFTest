"""Models package – registra todos los modelos con SQLAlchemy Base."""

from .tipo_ataque  import TipoAtaque
from .request_log  import PeticionLog
from .blocked_ip   import IPBloqueada
from .alert        import Alerta
from .auditoria    import AuditoriaSistema

__all__ = ["TipoAtaque", "PeticionLog", "IPBloqueada", "Alerta", "AuditoriaSistema"]
