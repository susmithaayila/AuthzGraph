import pytest
from app.engine.api_parser import APIParser
from app.engine.hybrid_policy import HybridPolicyEvaluator
from app.engine.object_graph import MultiUserObjectGraph, UserIdentity, ResourceObject
from app.engine.normalizer import ResponseNormalizer
from app.engine.reporter import Reporter
from app.core.guardrails import SafetyGuardrails

def test_openapi_parser():
    sample_spec = {
        "paths": {
            "/api/v1/vehicles/{vehicle_id}": {
                "get": {
                    "summary": "Get vehicle location",
                    "parameters": [{"name": "vehicle_id", "in": "path", "required": True}],
                    "responses": {"200": {"description": "Success"}}
                }
            }
        }
    }
    endpoints = APIParser.parse_spec(sample_spec)
    assert len(endpoints) == 1
    assert endpoints[0].method == "GET"
    assert "vehicle_id" in endpoints[0].path_param_names
    assert endpoints[0].sensitivity_label in ["CONFIDENTIAL", "SECRET", "INTERNAL"]

def test_hybrid_policy_evaluation():
    user = UserIdentity(user_id="u1", username="alice", token="tok", role_level=1, clearance="CONFIDENTIAL", attributes={"user_id": "u1"})
    res_owned = ResourceObject(object_id="r1", resource_type="doc", owner_user_id="u1", classification="CONFIDENTIAL")
    res_other = ResourceObject(object_id="r2", resource_type="doc", owner_user_id="u2", classification="SECRET")

    # Owned resource (ABAC allows owner match) -> True
    assert HybridPolicyEvaluator.evaluate(user, "READ", res_owned, required_role_level=1) == True
    # Secret resource above user clearance -> MAC blocks -> False
    assert HybridPolicyEvaluator.evaluate(user, "READ", res_other, required_role_level=1) == False


def test_scale_benchmark():
    result = HybridPolicyEvaluator.run_scale_benchmark(100)
    assert result["total_decisions"] == 100
    assert result["throughput_decisions_per_sec"] > 0

def test_response_normalizer():
    raw_payload = {"user": "alice", "created_at": "2026-07-27T10:00:00Z", "token": "secret123"}
    normalized = ResponseNormalizer.normalize_payload(raw_payload)
    assert normalized["created_at"] == "<BLINDED_VOLATILE_FIELD>"
    assert normalized["token"] == "<BLINDED_VOLATILE_FIELD>"
    assert normalized["user"] == "alice"

def test_safety_guardrails():
    guard = SafetyGuardrails(allowed_hosts=["localhost", "127.0.0.1"], safe_read_only=True)
    assert guard.validate_target_url("http://localhost:8080/api") == True
    assert guard.validate_target_url("http://malicious-external-site.com") == False
    assert guard.is_method_allowed("GET") == True
    assert guard.is_method_allowed("POST") == False
