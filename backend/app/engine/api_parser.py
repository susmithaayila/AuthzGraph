import re
from typing import Dict, List, Any, Optional
from pydantic import BaseModel

class APIEndpoint(BaseModel):
    id: str
    path: str
    method: str
    summary: Optional[str] = ""
    description: Optional[str] = ""
    parameters: List[Dict[str, Any]] = []
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schemas: Dict[str, Any] = {}
    path_param_names: List[str] = []
    query_param_names: List[str] = []
    produced_object_types: List[str] = []
    consumed_object_types: List[str] = []
    sensitivity_label: str = "INTERNAL"

class APIParser:
    """Parses OpenAPI v2/v3 specifications and extracts endpoint schemas, parameter metadata, and object references."""

    @staticmethod
    def parse_spec(spec_data: Dict[str, Any]) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        paths = spec_data.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Extract common path parameters if any
            common_params = path_item.get("parameters", [])

            for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                if method not in path_item:
                    continue

                op_data = path_item[method]
                endpoint_id = f"{method.upper()}_{path}"

                summary = op_data.get("summary", "")
                description = op_data.get("description", "")

                # Combine common and method-specific parameters
                all_params = list(common_params) + op_data.get("parameters", [])

                path_params = []
                query_params = []
                for param in all_params:
                    if isinstance(param, dict):
                        p_name = param.get("name")
                        p_in = param.get("in")
                        if p_in == "path" and p_name:
                            path_params.append(p_name)
                        elif p_in == "query" and p_name:
                            query_params.append(p_name)

                # Determine request body schema (OpenAPI v3 vs v2)
                req_schema = None
                if "requestBody" in op_data:
                    content = op_data["requestBody"].get("content", {})
                    json_media = content.get("application/json", {})
                    req_schema = json_media.get("schema")
                elif "parameters" in op_data:
                    for p in op_data["parameters"]:
                        if isinstance(p, dict) and p.get("in") == "body":
                            req_schema = p.get("schema")
                            break

                # Responses schema mapping
                resp_schemas = {}
                responses = op_data.get("responses", {})
                for code, resp_obj in responses.items():
                    if isinstance(resp_obj, dict):
                        if "content" in resp_obj:
                            c = resp_obj["content"].get("application/json", {})
                            resp_schemas[str(code)] = c.get("schema")
                        elif "schema" in resp_obj:
                            resp_schemas[str(code)] = resp_obj.get("schema")

                # Infer produced and consumed object types from path and parameter names
                consumed_types = APIParser._infer_consumed_objects(path, path_params, req_schema)
                produced_types = APIParser._infer_produced_objects(method, resp_schemas)

                # Infer sensitivity label from path/summary keywords
                sensitivity = APIParser._infer_sensitivity(path, summary, description)

                endpoint = APIEndpoint(
                    id=endpoint_id,
                    path=path,
                    method=method.upper(),
                    summary=summary,
                    description=description,
                    parameters=all_params,
                    request_body_schema=req_schema,
                    response_schemas=resp_schemas,
                    path_param_names=path_params,
                    query_param_names=query_params,
                    produced_object_types=produced_types,
                    consumed_object_types=consumed_types,
                    sensitivity_label=sensitivity
                )
                endpoints.append(endpoint)

        return endpoints

    @staticmethod
    def _infer_consumed_objects(path: str, path_params: List[str], req_schema: Optional[Dict[str, Any]]) -> List[str]:
        types = set()
        for p in path_params:
            clean_name = re.sub(r'(_id|Id|ID)$', '', p)
            types.add(clean_name.lower())

        segments = [s for s in path.split('/') if s and not s.startswith('{')]
        if segments:
            types.add(segments[-1].lower())

        return list(types)

    @staticmethod
    def _infer_produced_objects(method: str, resp_schemas: Dict[str, Any]) -> List[str]:
        types = set()
        if method.lower() in ["post", "put"]:
            success_schema = resp_schemas.get("200") or resp_schemas.get("201")
            if success_schema and isinstance(success_schema, dict):
                title = success_schema.get("title")
                if title:
                    types.add(title.lower())
        return list(types)

    @staticmethod
    def _infer_sensitivity(path: str, summary: str, description: str) -> str:
        text = f"{path} {summary} {description}".lower()
        if any(w in text for w in ["admin", "secret", "private", "credit", "ssn", "password", "token"]):
            return "SECRET"

        elif any(w in text for w in ["user", "account", "profile", "billing", "location"]):
            return "CONFIDENTIAL"
        elif any(w in text for w in ["public", "health", "ping", "info", "version"]):
            return "PUBLIC"
        return "INTERNAL"
