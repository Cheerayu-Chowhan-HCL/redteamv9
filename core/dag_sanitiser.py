"""
DagSanitiser — strips payloads and sensitive data before writing to DAG UI.
Raw data stays in SQLite only, never exposed via HTTP.
"""
import re
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Patterns that indicate injection payloads
_SQL_PATTERNS = [
    r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table|insert\s+into|update\s+set)",
    r"(?i)(or\s+1=1|and\s+1=1|'--|\"\s*--|\)\s*--)",
    r"(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
    r"(?i)(information_schema|sys\.tables|pg_sleep|xp_cmdshell)",
]
_XSS_PATTERNS = [
    r"(?i)<script[^>]*>.*?</script>",
    r"(?i)<[^>]+\s+on\w+\s*=",
    r"(?i)javascript\s*:",
    r"(?i)data:\s*text/html",
    r"(?i)<iframe[^>]*>",
    r"(?i)alert\s*\(",
    r"(?i)document\.cookie",
]
_CMD_PATTERNS = [
    r"(?i)(;|\|)\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)(?:\s|$)",
    r"(?i)\$\(.*?\)",
    r"(?i)`[^`]+`",
]
_B64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")

_ALL_COMPILED = [re.compile(p) for p in _SQL_PATTERNS + _XSS_PATTERNS + _CMD_PATTERNS]


class DagSanitiser:

    PLACEHOLDER = "[PAYLOAD REDACTED]"

    @classmethod
    def sanitise_string(cls, text: str) -> str:
        if not isinstance(text, str):
            return str(text)
        for pattern in _ALL_COMPILED:
            if pattern.search(text):
                return cls.PLACEHOLDER
        # Strip base64 blobs
        text = _B64_PATTERN.sub("[B64 REDACTED]", text)
        return text

    @classmethod
    def sanitise_node(cls, node: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitise a DAG node dict before HTTP exposure."""
        safe = {}
        for k, v in node.items():
            if k in ("payload", "injection_value", "raw_body", "response_body"):
                safe[k] = cls.PLACEHOLDER
            elif k == "cookies" and isinstance(v, dict):
                safe[k] = {ck: "[REDACTED]" for ck in v}
            elif k == "cookies" and isinstance(v, str):
                safe[k] = "[COOKIE REDACTED]"
            elif k in ("method", "url", "status_code", "content_length", "endpoint", "parameter"):
                safe[k] = v  # keep structural metadata
            elif isinstance(v, str):
                safe[k] = cls.sanitise_string(v)
            elif isinstance(v, dict):
                safe[k] = cls.sanitise_node(v)
            elif isinstance(v, list):
                safe[k] = [cls.sanitise_node(i) if isinstance(i, dict)
                            else cls.sanitise_string(i) if isinstance(i, str)
                            else i for i in v]
            else:
                safe[k] = v
        return safe

    @classmethod
    def sanitise_evidence(cls, evidence: str) -> str:
        """Sanitise evidence string — keep only high-level summary."""
        if not isinstance(evidence, str):
            return str(evidence)
        sanitised = cls.sanitise_string(evidence)
        if len(sanitised) > 300:
            sanitised = sanitised[:300] + "... [TRUNCATED]"
        return sanitised
