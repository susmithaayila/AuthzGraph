import time
from typing import Dict, Any
from app.engine.object_graph import UserIdentity, ResourceObject

CLEARANCE_LEVELS = {"PUBLIC": 1, "INTERNAL": 2, "CONFIDENTIAL": 3, "SECRET": 4}


class HybridPolicyEvaluator:
    """
    Evaluates policy decisions using formal Hybrid Access Control model:
    Decision(subject, action, object, context) =
        MAC_allows(subject.clearance, object.classification)
        AND ( RBAC_allows(subject.role_level, required_role_level)
              OR ABAC_allows(subject.attrs, object.attrs, context) )
    """

    @staticmethod
    def mac_allows(clearance: str, classification: str) -> bool:
        """Bell-LaPadula mandatory sensitivity lattice: No Read Up / No Access Above Clearance."""
        subject_level = CLEARANCE_LEVELS.get(clearance.upper(), 0)
        object_level = CLEARANCE_LEVELS.get(classification.upper(), 0)
        return subject_level >= object_level

    @staticmethod
    def rbac_allows(user_role_level: int, required_role_level: int) -> bool:
        """Coarse role hierarchy check."""
        return user_role_level >= required_role_level

    @staticmethod
    def abac_allows(user_attrs: Dict[str, Any], object_attrs: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Contextual attribute check (e.g. object owner match, time-of-day, IP reputation)."""
        # Owner match condition
        if object_attrs.get("owner_user_id") and user_attrs.get("user_id"):
            if object_attrs.get("owner_user_id") == user_attrs.get("user_id"):
                return True
        # Department match condition
        if user_attrs.get("department") and object_attrs.get("department"):
            if user_attrs.get("department") == object_attrs.get("department"):
                return True
        return False

    @classmethod
    def evaluate(cls, user: UserIdentity, action: str, resource: ResourceObject, required_role_level: int = 1, context: Dict[str, Any] = None) -> bool:
        context = context or {}

        # Guardrail MAC check
        if not cls.mac_allows(user.clearance, resource.classification):
            return False

        # RBAC or ABAC evaluation
        rbac_result = cls.rbac_allows(user.role_level, required_role_level)
        abac_result = cls.abac_allows(user.attributes, resource.attributes, context)

        return rbac_result or abac_result

    @classmethod
    def run_scale_benchmark(cls, population_size: int = 1000) -> Dict[str, Any]:
        """Runs scale evaluation across synthetic identity graph (1K / 10K / 100K users)."""
        start_time = time.time()
        decisions_made = 0

        # Simulate Zipfian identity distribution
        for i in range(population_size):
            user = UserIdentity(
                user_id=f"user_{i}",
                username=f"synthetic_user_{i}",
                token=f"token_{i}",
                role_level=1 if i % 10 != 0 else 3,
                clearance="INTERNAL" if i % 5 != 0 else "CONFIDENTIAL",
                attributes={"user_id": f"user_{i}", "department": "engineering" if i % 2 == 0 else "sales"}
            )
            resource = ResourceObject(
                object_id=f"res_{i}",
                resource_type="document",
                owner_user_id=f"user_{i}",
                classification="INTERNAL"
            )
            cls.evaluate(user, "READ", resource, required_role_level=1)
            decisions_made += 1

        elapsed = max(time.time() - start_time, 0.000001)
        latency_ms_per_decision = (elapsed / decisions_made) * 1000 if decisions_made > 0 else 0
        throughput = decisions_made / elapsed if elapsed > 0 else 0

        return {
            "population_size": population_size,
            "total_decisions": decisions_made,
            "total_time_seconds": round(elapsed, 4),
            "latency_ms_per_decision": round(latency_ms_per_decision, 6),
            "throughput_decisions_per_sec": round(throughput, 2)
        }
