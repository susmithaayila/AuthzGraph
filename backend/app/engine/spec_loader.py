"""
SpecLoader — loads OpenAPI v2/v3 specs from a URL or raw text,
then parses them into APIEndpoint objects using the existing APIParser.
"""

import json
from typing import List, Optional
import httpx
import yaml

from app.engine.api_parser import APIParser, APIEndpoint


class SpecLoader:
    # Module-level state — persists between requests
    loaded_endpoints: List[APIEndpoint] = []
    spec_title: str = ""
    spec_source: str = ""        # "url" | "upload"
    spec_url: Optional[str] = None
    endpoint_count: int = 0

    @classmethod
    async def load_from_url(cls, url: str) -> List[APIEndpoint]:
        """Fetches an OpenAPI spec from a URL and parses it."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.get(url, follow_redirects=True)
            res.raise_for_status()
            content_type = res.headers.get("content-type", "")
            if "yaml" in content_type or url.endswith((".yaml", ".yml")):
                data = yaml.safe_load(res.text)
            else:
                data = res.json()

        endpoints = APIParser.parse_spec(data)
        cls.loaded_endpoints = endpoints
        cls.spec_title = data.get("info", {}).get("title", "Loaded Spec")
        cls.spec_source = "url"
        cls.spec_url = url
        cls.endpoint_count = len(endpoints)
        return endpoints

    @classmethod
    def load_from_text(cls, content: str) -> List[APIEndpoint]:
        """Parses a raw OpenAPI JSON or YAML string."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = yaml.safe_load(content)

        if not isinstance(data, dict):
            raise ValueError("Invalid OpenAPI spec: must be a JSON/YAML object")

        endpoints = APIParser.parse_spec(data)
        cls.loaded_endpoints = endpoints
        cls.spec_title = data.get("info", {}).get("title", "Uploaded Spec")
        cls.spec_source = "upload"
        cls.spec_url = None
        cls.endpoint_count = len(endpoints)
        return endpoints

    @classmethod
    def clear(cls) -> None:
        cls.loaded_endpoints = []
        cls.spec_title = ""
        cls.spec_source = ""
        cls.spec_url = None
        cls.endpoint_count = 0

    @classmethod
    def to_dict_list(cls) -> list:
        """Returns loaded endpoints as plain dicts for JSON serialisation."""
        return [
            {
                "id": ep.id,
                "method": ep.method,
                "path": ep.path,
                "summary": ep.summary,
                "sensitivity_label": ep.sensitivity_label,
                "path_param_names": ep.path_param_names,
            }
            for ep in cls.loaded_endpoints
        ]
