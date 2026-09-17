from typing import Dict, List
import re
from app.engine.api_parser import APIEndpoint

class RequestDependencyGraph:
    """
    RESTler-inspired Request Dependency Graph (ICSE '19).
    Infers producer-consumer relationships between REST API endpoints to generate stateful sequences.
    """
    def __init__(self, endpoints: List[APIEndpoint]):
        self.endpoints = endpoints
        # Maps object_type -> list of producer endpoints (e.g. POST endpoints returning object_type)
        self.producers: Dict[str, List[APIEndpoint]] = {}
        # Maps object_type -> list of consumer endpoints (e.g. GET /vehicles/{id} accepting object_type)
        self.consumers: Dict[str, List[APIEndpoint]] = {}
        self._build_graph()

    def _build_graph(self):
        for ep in self.endpoints:
            # Check for path parameter consumers
            for param_name in ep.path_param_names:
                clean_type = re.sub(r'(_id|Id|ID)$', '', param_name).lower()
                if clean_type not in self.consumers:
                    self.consumers[clean_type] = []
                self.consumers[clean_type].append(ep)

            # Check for producers (POST / PUT endpoints)
            if ep.method in ["POST", "PUT"]:
                for prod_type in ep.produced_object_types:
                    if prod_type not in self.producers:
                        self.producers[prod_type] = []
                    self.producers[prod_type].append(ep)

                # Fallback: Infer produced type from path basename if list is empty
                path_base = ep.path.strip('/').split('/')[-1]
                path_type = re.sub(r'[^a-zA-Z0-9]', '', path_base).lower()
                if path_type and path_type not in self.producers:
                    self.producers[path_type] = []
                if path_type:
                    self.producers[path_type].append(ep)

    def get_producers_for_consumer(self, consumer_endpoint: APIEndpoint) -> List[APIEndpoint]:
        matching_producers = []
        for param in consumer_endpoint.path_param_names:
            clean_param = re.sub(r'(_id|Id|ID)$', '', param).lower()
            for prod_type, prods in self.producers.items():
                if prod_type in clean_param or clean_param in prod_type:
                    matching_producers.extend(prods)
        return list(set(matching_producers))

    def generate_execution_order(self) -> List[APIEndpoint]:
        """Generates topological execution order putting setup (POST) endpoints before Dependent (GET/PUT/DELETE) endpoints."""
        posts = [ep for ep in self.endpoints if ep.method == "POST"]
        gets = [ep for ep in self.endpoints if ep.method == "GET"]
        others = [ep for ep in self.endpoints if ep.method not in ["POST", "GET"]]
        return posts + gets + others
