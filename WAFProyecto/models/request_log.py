from database import db
from datetime import datetime


class RequestLog(db.Model):
    """Logs every HTTP request that passes through the WAF proxy."""

    __tablename__ = "request_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)       # IPv4 or IPv6
    method = db.Column(db.String(10), nullable=False)           # GET, POST, …
    path = db.Column(db.String(2048), nullable=False)
    user_agent = db.Column(db.String(512), nullable=True)
    risk_score = db.Column(db.Float, default=0.0, nullable=False)
    action = db.Column(db.String(20), default="allow", nullable=False)  # allow/block
    attack_type = db.Column(db.String(100), nullable=True)      # sqli, xss, …
    rule_hits = db.Column(db.Text, nullable=True)               # JSON list of rule ids
    status_code = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ip_address": self.ip_address,
            "method": self.method,
            "path": self.path,
            "user_agent": self.user_agent,
            "risk_score": self.risk_score,
            "action": self.action,
            "attack_type": self.attack_type,
            "rule_hits": self.rule_hits,
            "status_code": self.status_code,
        }

    def __repr__(self):
        return f"<RequestLog {self.id} {self.method} {self.path} [{self.action}]>"
