import urllib.parse
from typing import List
from pydantic import BaseModel, Field

class SafetyGuardrails(BaseModel):
    allowed_hosts: List[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "0.0.0.0", "crapi.local", "vampi.local"])
    dry_run: bool = False
    safe_read_only: bool = False
    max_requests_per_second: float = 20.0
    auto_teardown: bool = True

    def validate_target_url(self, target_url: str) -> bool:
        """Validates that target URL is within configured allowed hosts."""
        try:
            parsed = urllib.parse.urlparse(target_url)
            hostname = parsed.hostname or ""
            if not hostname:
                return False
            return any(host in hostname.lower() for host in self.allowed_hosts)
        except Exception:
            return False

    def is_method_allowed(self, method: str) -> bool:
        """Enforces safe_read_only mode when active."""
        if self.safe_read_only:
            return method.upper() in ["GET", "HEAD", "OPTIONS"]
        return True
