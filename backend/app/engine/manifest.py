from typing import Dict, List, Any, Optional
import yaml
from pydantic import BaseModel, Field

class PrivilegeManifest(BaseModel):
    version: str = "1.0"
    target_name: str = "Target Microservice"
    roles: List[Dict[str, Any]] = Field(default_factory=list)
    endpoints: List[Dict[str, Any]] = Field(default_factory=list)
    sensitive_properties: List[Dict[str, Any]] = Field(default_factory=list)

    @classmethod
    def load_from_yaml(cls, filepath: str) -> "PrivilegeManifest":
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def get_endpoint_requirement(self, path: str, method: str) -> Optional[str]:
        for ep in self.endpoints:
            if ep.get("path") == path and method.upper() in ep.get("methods", []):
                return ep.get("required_role")
        return None

    def get_sensitive_properties(self) -> List[str]:
        return [prop.get("property_name") for prop in self.sensitive_properties if prop.get("property_name")]
