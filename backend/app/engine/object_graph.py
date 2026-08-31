import networkx as nx
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class UserIdentity(BaseModel):
    user_id: str
    username: str
    token: str
    role: str = "USER_REGULAR"
    role_level: int = 1
    attributes: Dict[str, Any] = Field(default_factory=dict)
    clearance: str = "INTERNAL"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

class ResourceObject(BaseModel):
    object_id: str
    resource_type: str
    owner_user_id: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    classification: str = "INTERNAL"

class MultiUserObjectGraph:
    """
    NetworkX-powered stateful multi-user object ownership graph.
    Tracks User -> Token -> ResourceObject -> Endpoint relationships live.
    """
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_user(self, user: UserIdentity):
        self.graph.add_node(
            user.user_id,
            type="USER",
            username=user.username,
            role=user.role,
            role_level=user.role_level,
            clearance=user.clearance,
            token=user.token
        )

    def add_resource(self, resource: ResourceObject):
        self.graph.add_node(
            resource.object_id,
            type="RESOURCE",
            resource_type=resource.resource_type,
            classification=resource.classification,
            owner_user_id=resource.owner_user_id
        )
        # Add ownership edge
        if self.graph.has_node(resource.owner_user_id):
            self.graph.add_edge(resource.owner_user_id, resource.object_id, relationship="OWNS")

    def get_user_resources(self, user_id: str) -> List[str]:
        if not self.graph.has_node(user_id):
            return []
        return [target for _, target, data in self.graph.out_edges(user_id, data=True) if data.get("relationship") == "OWNS"]

    def get_substitution_pairs(self, owner_user_id: str, attacker_user_id: str) -> List[Dict[str, str]]:
        """Generates (target_object_id, owner_id) pairs owned by User A to test against User B."""
        owner_objs = self.get_user_resources(owner_user_id)
        return [{"object_id": obj_id, "owner_user_id": owner_user_id} for obj_id in owner_objs]

    def to_react_flow_json(self) -> Dict[str, Any]:
        """Exports graph state into React Flow nodes and edges format."""
        nodes = []
        edges = []

        for node_id, attrs in self.graph.nodes(data=True):
            node_type = attrs.get("type", "UNKNOWN")
            nodes.append({
                "id": node_id,
                "type": node_type.lower(),
                "data": {
                    "label": f"{node_type}: {attrs.get('username') or attrs.get('resource_type') or node_id}",
                    "details": attrs
                },
                "position": {"x": 100, "y": 100}  # Positions layed out by React Flow
            })

        for src, dst, data in self.graph.edges(data=True):
            edges.append({
                "id": f"{src}->{dst}",
                "source": src,
                "target": dst,
                "label": data.get("relationship", "CONNECTED"),
                "animated": data.get("relationship") == "OWNS"
            })

        return {"nodes": nodes, "edges": edges}
