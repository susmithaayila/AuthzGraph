from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from app.api.routes import router as api_router

# Security scheme — this makes the "Authorize" button appear in /docs (Swagger UI)
bearer_scheme = HTTPBearer(
    scheme_name="Bearer Token",
    description="Paste your JWT or Bearer token here (without the 'Bearer ' prefix). "
                "This token will be sent as `Authorization: Bearer <token>` on every request.",
    auto_error=False,   # Don't block unauthenticated requests — endpoints handle auth themselves
)

app = FastAPI(
    title="AuthzGraph API Security Platform",
    description="Automated REST API Authorization Vulnerability Tester & Hybrid Access Control Engine",
    version="1.0.0",
    swagger_ui_parameters={
        "persistAuthorization": True,   # Keep token across page reloads
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_engine_latency_header(request, call_next):
    import time
    from app.engine.authz_engine import CentralAuthorizationEngine
    t0 = time.perf_counter()
    response = await call_next(request)
    t1 = time.perf_counter()
    duration_ms = (t1 - t0) * 1000.0
    engine_ms = getattr(CentralAuthorizationEngine, "last_evaluation_latency_ms", duration_ms)
    response.headers["X-AuthzEngine-Latency-Ms"] = f"{engine_ms:.3f}"
    return response


app.include_router(api_router, prefix="/api/v1", dependencies=[Depends(bearer_scheme)])

@app.get("/")
async def root():
    return {"message": "AuthzGraph Backend Engine is running. Access API docs at /docs"}
