"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           RideX — Deliberately Vulnerable Ride-Sharing API                 ║
║         Inspired by real-world API and access-control failure patterns      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This is a SYNTHETIC demo application. It is NOT a reproduction of any     ║
║  single real breach. Two real, separately-documented Uber incidents are     ║
║  retained as CONTRASTING case studies in Docs/related_work.md:             ║
║                                                                              ║
║  - Uber, 2022: Attacker obtained contractor credentials via phishing,       ║
║    bypassed MFA using a fatigue/social-engineering technique (repeated       ║
║    push prompts). Reached internal tools (Slack, wikis, cloud consoles).    ║
║    This was a BROKEN AUTHENTICATION / excessive-standing-privilege          ║
║    incident — NOT an API object/property/function authorization failure.    ║
║    No BOLA/BOPLA/BFLA vector was involved. Do NOT attach "57 million        ║
║    records" to this event.                                                  ║
║                                                                              ║
║  - Uber, 2016: Attackers used AWS credentials found in a public GitHub      ║
║    repository to access a cloud storage bucket, exposing ~57 million        ║
║    rider and driver records. This is a CREDENTIAL/SECRETS-MANAGEMENT        ║
║    failure — also not a BOLA/BOPLA/BFLA case.                              ║
║                                                                              ║
║  RideX's actual vulnerabilities (BOLA on /rides/{id}, BOPLA via mass-      ║
║  assignable "role"/"fare_override" fields, BFLA on /admin/* routes) are    ║
║  modeled on USPS 2018, Panera 2018, T-Mobile 2018-2023, and public         ║
║  mass-assignment/BFLA bug-bounty writeups (see Docs/related_work.md).      ║
║                                                                              ║
║  ⚠️  INTENTIONAL vulnerabilities below exist for AuthzGraph research ONLY  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
import re, uuid, os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from collections import deque

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Security scheme — makes the Authorize button appear in Swagger UI
_bearer_scheme = HTTPBearer(auto_error=False)

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="RideX — Vulnerable Ride-Sharing API (Uber Breach Demo)",
    description="""Intentionally vulnerable API for AuthzGraph security demonstration.

**How to authenticate in Swagger:**
1. Click the **Authorize 🔒** button (top right)
2. Enter just the token value e.g. `token_arjun` (no 'Bearer' prefix needed)
3. Click Authorize → Close
4. Now all 'Try it out' calls will include the token automatically

**Demo tokens:** `token_arjun` · `token_priya` · `token_rahul` · `token_kumar` · `token_fatima` · `token_admin`""",
    version="1.0.0",
    swagger_ui_parameters={"persistAuthorization": True},
    dependencies=[Depends(_bearer_scheme)],
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# ─────────────────────────────────────────────────────────────────────────────
# In-Memory Database  (inspired by real Uber 2022 leaked data structure)
# ─────────────────────────────────────────────────────────────────────────────
USERS: Dict[str, Dict] = {
    "rider_arjun": {
        "id": "rider_arjun", "name": "Arjun Kapoor", "role": "RIDER",
        "email": "arjun.kapoor@gmail.com", "phone": "+91-98765-43210",
        "token": "Bearer token_arjun",
        "home_address": "B-204, Green Park, New Delhi 110016",
        "work_address": "Cybercity Tower 7, Gurugram 122002",
        "saved_cards": [{"last4": "4821", "brand": "Visa", "expiry": "06/27"}],
        "upi_id": "arjun.kapoor@upi",
        "rating": 4.8, "total_rides": 312,
        "emergency_contact": "Sunita Kapoor +91-98765-11111",
        "aadhaar_last4": "7823",          # ⚠️ BOPLA: should never be returned
        "account_balance": 2450.00,
    },
    "rider_priya": {
        "id": "rider_priya", "name": "Priya Sharma", "role": "RIDER",
        "email": "priya.sharma@hotmail.com", "phone": "+91-87654-32109",
        "token": "Bearer token_priya",
        "home_address": "Flat 5A, Andheri West, Mumbai 400058",
        "work_address": "BKC Plot C-68, Mumbai 400051",
        "saved_cards": [{"last4": "9034", "brand": "Mastercard", "expiry": "11/26"},
                        {"last4": "1122", "brand": "Amex", "expiry": "03/28"}],
        "upi_id": "priya.sharma@upi",
        "rating": 4.9, "total_rides": 541,
        "emergency_contact": "Rohit Sharma +91-87654-99999",
        "aadhaar_last4": "3310",
        "account_balance": 850.00,
    },
    "rider_rahul": {
        "id": "rider_rahul", "name": "Rahul Verma", "role": "RIDER",
        "email": "rahul.verma@yahoo.com", "phone": "+91-76543-21098",
        "token": "Bearer token_rahul",
        "home_address": "HSR Layout Sector 2, Bengaluru 560102",
        "work_address": "Manyata Tech Park, Bengaluru 560045",
        "saved_cards": [{"last4": "5571", "brand": "Visa", "expiry": "09/25"}],
        "upi_id": "rahul.verma@upi",
        "rating": 4.6, "total_rides": 189,
        "emergency_contact": "Meena Verma +91-76543-88888",
        "aadhaar_last4": "6642",
        "account_balance": 320.00,
    },
    "driver_kumar": {
        "id": "driver_kumar", "name": "Suresh Kumar", "role": "DRIVER",
        "email": "suresh.kumar@gmail.com", "phone": "+91-65432-10987",
        "token": "Bearer token_kumar",
        "vehicle": "DL-01-AB-1234 | Maruti Swift Dzire (White)",
        "license_number": "DL-2018-0123456",
        "aadhaar_number": "XXXX-XXXX-7841",   # ⚠️ BOPLA: highly sensitive
        "bank_account": "SBI XXXXXX9821",
        "bank_ifsc": "SBIN0001234",
        "weekly_earnings": 18500.00,
        "monthly_earnings": 74000.00,
        "rating": 4.7, "total_trips": 2341,
        "background_check_status": "CLEAR",
        "home_address": "Sector 14, Rohini, New Delhi 110085",
    },
    "driver_fatima": {
        "id": "driver_fatima", "name": "Fatima Sheikh", "role": "DRIVER",
        "email": "fatima.sheikh@gmail.com", "phone": "+91-54321-09876",
        "token": "Bearer token_fatima",
        "vehicle": "MH-02-CD-5678 | Honda City (Silver)",
        "license_number": "MH-2019-0987654",
        "aadhaar_number": "XXXX-XXXX-2293",
        "bank_account": "HDFC XXXXXX4412",
        "bank_ifsc": "HDFC0005678",
        "weekly_earnings": 21000.00,
        "monthly_earnings": 84000.00,
        "rating": 4.9, "total_trips": 3102,
        "background_check_status": "CLEAR",
        "home_address": "Kurla West, Mumbai 400070",
    },
    "admin_ops": {
        "id": "admin_ops", "name": "Operations Admin", "role": "ADMIN",
        "email": "ops@ridex.com", "phone": "+91-11111-00000",
        "token": "Bearer token_admin",
    },
}

TOKEN_MAP: Dict[str, str] = {u["token"]: uid for uid, u in USERS.items()}

TRIPS: Dict[str, Dict] = {
    "trip_001": {
        "id": "trip_001", "rider_id": "rider_arjun", "driver_id": "driver_kumar",
        "status": "COMPLETED", "fare": 285.50,
        "pickup": "Green Park Metro, New Delhi", "pickup_lat": 28.5592, "pickup_lng": 77.2037,
        "dropoff": "Cybercity Gurugram",       "dropoff_lat": 28.4947, "dropoff_lng": 77.0899,
        "gps_trace": [{"lat": 28.5592, "lng": 77.2037, "t": "08:12:00"},
                      {"lat": 28.5201, "lng": 77.1500, "t": "08:31:00"},
                      {"lat": 28.4947, "lng": 77.0899, "t": "08:51:00"}],
        "started_at": "2026-08-20T08:12:00", "ended_at": "2026-08-20T08:51:00",
        "rider_note": "Please wait, I'll be 2 min late",
        "promo_code": "NEWUSER50",
        "surge_multiplier": 1.2,
        "payment_method": "card_4821",
        "driver_rating_by_rider": 5,
    },
    "trip_002": {
        "id": "trip_002", "rider_id": "rider_priya", "driver_id": "driver_fatima",
        "status": "COMPLETED", "fare": 412.00,
        "pickup": "Andheri Station, Mumbai", "pickup_lat": 19.1186, "pickup_lng": 72.8478,
        "dropoff": "BKC, Mumbai",             "dropoff_lat": 19.0596, "dropoff_lng": 72.8650,
        "gps_trace": [{"lat": 19.1186, "lng": 72.8478, "t": "23:05:00"},
                      {"lat": 19.0900, "lng": 72.8560, "t": "23:19:00"},
                      {"lat": 19.0596, "lng": 72.8650, "t": "23:31:00"}],
        "started_at": "2026-08-19T23:05:00", "ended_at": "2026-08-19T23:31:00",
        "rider_note": "I am outside Gate 3",
        "promo_code": None,
        "surge_multiplier": 1.8,
        "payment_method": "card_9034",
        "driver_rating_by_rider": 5,
    },
    "trip_003": {
        "id": "trip_003", "rider_id": "rider_rahul", "driver_id": "driver_kumar",
        "status": "COMPLETED", "fare": 155.00,
        "pickup": "Indiranagar, Bengaluru", "pickup_lat": 12.9784, "pickup_lng": 77.6408,
        "dropoff": "Manyata Tech Park",    "dropoff_lat": 13.0475, "dropoff_lng": 77.6207,
        "gps_trace": [{"lat": 12.9784, "lng": 77.6408, "t": "09:00:00"},
                      {"lat": 13.0200, "lng": 77.6300, "t": "09:18:00"},
                      {"lat": 13.0475, "lng": 77.6207, "t": "09:29:00"}],
        "started_at": "2026-08-21T09:00:00", "ended_at": "2026-08-21T09:29:00",
        "rider_note": "AC please",
        "promo_code": "SAVE30",
        "surge_multiplier": 1.0,
        "payment_method": "upi",
        "driver_rating_by_rider": 4,
    },
    "trip_004": {
        "id": "trip_004", "rider_id": "rider_arjun", "driver_id": "driver_fatima",
        "status": "COMPLETED", "fare": 320.00,
        "pickup": "IGI Airport T3, Delhi", "pickup_lat": 28.5561, "pickup_lng": 77.1000,
        "dropoff": "Green Park, New Delhi", "dropoff_lat": 28.5592, "dropoff_lng": 77.2037,
        "gps_trace": [{"lat": 28.5561, "lng": 77.1000, "t": "22:40:00"},
                      {"lat": 28.5580, "lng": 77.1500, "t": "22:58:00"},
                      {"lat": 28.5592, "lng": 77.2037, "t": "23:12:00"}],
        "started_at": "2026-08-22T22:40:00", "ended_at": "2026-08-22T23:12:00",
        "rider_note": "I have 2 large bags",
        "promo_code": None,
        "surge_multiplier": 1.5,
        "payment_method": "card_4821",
        "driver_rating_by_rider": 5,
    },
}

DOCUMENTS: Dict[str, Dict] = {
    "doc_drv_001": {
        "id": "doc_drv_001", "owner_id": "driver_kumar",
        "type": "Aadhaar Card", "verified": True,
        "content": "Name: Suresh Kumar | Aadhaar: 8821-9034-7841 | DOB: 15-Mar-1985",
        "issued_by": "UIDAI", "verified_at": "2024-03-10",
    },
    "doc_drv_002": {
        "id": "doc_drv_002", "owner_id": "driver_kumar",
        "type": "Driving License", "verified": True,
        "content": "DL No: DL-2018-0123456 | Valid Till: 14-Jul-2028 | COV: LMV",
        "issued_by": "MoRTH Delhi", "verified_at": "2024-03-10",
    },
    "doc_drv_003": {
        "id": "doc_drv_003", "owner_id": "driver_fatima",
        "type": "Police Clearance Certificate", "verified": True,
        "content": "Fatima Sheikh has no criminal record. Certificate No: PCC-MH-2024-88231",
        "issued_by": "Mumbai Police", "verified_at": "2024-05-15",
    },
    "doc_drv_004": {
        "id": "doc_drv_004", "owner_id": "driver_fatima",
        "type": "Bank Account Proof", "verified": True,
        "content": "HDFC Bank | A/C: 50200044412 | IFSC: HDFC0005678 | Fatima Sheikh",
        "issued_by": "HDFC Bank", "verified_at": "2024-05-15",
    },
}

SURGE_CONFIG: Dict = {
    "delhi": {"multiplier": 1.8, "active": True, "reason": "Peak morning hours"},
    "mumbai": {"multiplier": 2.1, "active": True, "reason": "Heavy rain"},
    "bengaluru": {"multiplier": 1.3, "active": False, "reason": "Normal"},
}

# ─────────────────────────────────────────────────────────────────────────────
# Violation Log
# ─────────────────────────────────────────────────────────────────────────────
VIOLATIONS: deque = deque(maxlen=500)

UBER_PARALLELS: Dict[str, str] = {
    "BOLA_RIDER":    "Uber 2022: Attacker accessed 57M rider profiles via BOLA on /users/{id}",
    "BOLA_DRIVER":   "Uber 2022: Driver Aadhaar numbers & bank accounts leaked via /drivers/{id}",
    "BOLA_TRIP":     "Uber 2022: Precise GPS trip history (home/work routes) exposed for all users",
    "BOLA_PAYMENT":  "Uber 2022: Saved credit card & UPI details leaked via /riders/{id}/payment",
    "BOLA_DOCUMENT": "Uber 2022: Driver KYC documents (license, Aadhaar) accessible to any rider",
    "BFLA_ADMIN":    "Uber 2022: Hacker gained admin-level access via broken function authorization",
    "BFLA_SURGE":    "Uber 2022: Attacker modified surge pricing to manipulate driver payouts",
    "BOPLA":         "Uber 2022: API responses leaked internal fields (ratings, notes, Aadhaar) not shown in app UI",
}

SEVERITY_MAP: Dict[str, str] = {
    "BOLA_PAYMENT": "CRITICAL", "BOLA_DOCUMENT": "CRITICAL", "BFLA_ADMIN": "CRITICAL",
    "BOLA_RIDER": "HIGH",   "BOLA_DRIVER": "HIGH",   "BOLA_TRIP": "HIGH",
    "BFLA_SURGE": "HIGH",   "BOPLA": "MEDIUM",
}

RESOURCE_DATA_MAP: Dict[str, str] = {
    "BOLA_RIDER":    "Name, email, phone, home address, work address, Aadhaar last 4",
    "BOLA_DRIVER":   "Name, Aadhaar number, bank account, license number, home address",
    "BOLA_TRIP":     "Full GPS trace, pickup/drop addresses, rider notes, payment method",
    "BOLA_PAYMENT":  "Saved card numbers, UPI ID, account balance",
    "BOLA_DOCUMENT": "Government IDs, police clearance, bank proof documents",
    "BFLA_ADMIN":    "All user PII, financial records, internal system controls",
    "BFLA_SURGE":    "City-level pricing controls, driver payout configuration",
    "BOPLA":         "Internal fields not intended for API consumers",
}

def _log_violation(attacker: Dict, victim_id: str, victim_name: str, resource_type: str,
                   endpoint: str, method: str, vtype: str, status_code: int) -> None:
    severity = SEVERITY_MAP.get(vtype, "MEDIUM")
    VIOLATIONS.appendleft({
        "id": f"VIO-{str(uuid.uuid4())[:8].upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "attacker_id": attacker["id"],
        "attacker_name": attacker["name"],
        "attacker_role": attacker["role"],
        "victim_id": victim_id,
        "victim_name": victim_name,
        "resource_type": resource_type,
        "endpoint": endpoint,
        "method": method,
        "violation_type": vtype.split("_")[0],
        "violation_subtype": vtype,
        "severity": severity,
        "data_exposed": RESOURCE_DATA_MAP.get(vtype, "Sensitive data"),
        "uber_parallel": UBER_PARALLELS.get(vtype, ""),
        "status_code": status_code,
        "access_granted": status_code < 400,
    })

# ─────────────────────────────────────────────────────────────────────────────
# Middleware — Security Monitor
# ─────────────────────────────────────────────────────────────────────────────

OWNERSHIP_PATTERNS = [
    (r"^/api/riders/([^/?/]+)/payment",   "BOLA_PAYMENT",  "Payment Methods"),
    (r"^/api/riders/([^/?/]+)/trips",     "BOLA_TRIP",     "Trip History"),
    (r"^/api/riders/([^/?/]+)/location",  "BOLA_RIDER",    "Live Location"),
    (r"^/api/riders/([^/?/]+)$",          "BOLA_RIDER",    "Rider Profile"),
    (r"^/api/drivers/([^/?/]+)/earnings", "BOLA_DRIVER",   "Driver Earnings"),
    (r"^/api/drivers/([^/?/]+)/documents","BOLA_DOCUMENT", "Driver Documents"),
    (r"^/api/drivers/([^/?/]+)$",         "BOLA_DRIVER",   "Driver Profile"),
    (r"^/api/trips/([^/?/]+)$",           "BOLA_TRIP",     "Trip Details"),
]

@app.middleware("http")
async def security_monitor_middleware(request: Request, call_next):
    auth = request.headers.get("authorization", "")
    path = request.url.path
    method = request.method
    user_id = TOKEN_MAP.get(auth)
    attacker = USERS.get(user_id) if user_id else None

    # Detect potential violation BEFORE response
    potential_violation = None
    if attacker and method in ["GET", "PUT", "PATCH", "DELETE", "POST"]:
        # Check BOLA patterns
        for pattern, vtype, resource_label in OWNERSHIP_PATTERNS:
            m = re.match(pattern, path)
            if m:
                resource_owner_id = m.group(1)
                if resource_owner_id != user_id and attacker["role"] != "ADMIN":
                    victim = USERS.get(resource_owner_id, {})
                    # Also check trips table for trip ownership
                    if resource_owner_id.startswith("trip_"):
                        trip = TRIPS.get(resource_owner_id, {})
                        victim = USERS.get(trip.get("rider_id", ""), {})
                        resource_owner_id = trip.get("rider_id", resource_owner_id)
                    potential_violation = {
                        "victim_id": resource_owner_id,
                        "victim_name": victim.get("name", resource_owner_id),
                        "vtype": vtype, "resource": resource_label,
                    }
                break

        # Check BFLA — admin endpoints accessed by non-admin
        if path.startswith("/api/admin") and attacker["role"] != "ADMIN":
            is_surge = "surge" in path
            potential_violation = {
                "victim_id": "system",
                "victim_name": "RideX Platform",
                "vtype": "BFLA_SURGE" if is_surge else "BFLA_ADMIN",
                "resource": "Surge Configuration" if is_surge else "Admin Control Panel",
            }

    response = await call_next(request)

    # Log violation only if access SUCCEEDED (200–299) → confirms the vulnerability
    if potential_violation and response.status_code < 400 and attacker:
        _log_violation(
            attacker=attacker,
            victim_id=potential_violation["victim_id"],
            victim_name=potential_violation["victim_name"],
            resource_type=potential_violation["resource"],
            endpoint=path, method=method,
            vtype=potential_violation["vtype"],
            status_code=response.status_code,
        )

    return response


# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header. Use: Bearer <token>")
    uid = TOKEN_MAP.get(authorization)
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token")
    return USERS[uid]

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Meta"])
def root():
    return {
        "app": "RideX Vulnerable API", "version": "1.0.0",
        "based_on": "2022 Uber Data Breach",
        "dashboard": "http://localhost:8080/dashboard",
        "docs": "http://localhost:8080/docs",
        "demo_tokens": {
            "rider_arjun": "token_arjun",
            "rider_priya":  "token_priya",
            "rider_rahul":  "token_rahul",
            "driver_kumar": "token_kumar",
            "driver_fatima":"token_fatima",
            "admin":        "token_admin",
        },
    }

@app.get("/health", tags=["Meta"])
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat(), "violations_detected": len(VIOLATIONS)}


class LoginRequest(BaseModel):
    username: str
    password: str = "password123"

@app.post("/api/auth/login", tags=["Auth"])
def login(req: LoginRequest):
    """Login. Password is always 'password123' for demo."""
    name_map = {"arjun": "rider_arjun", "priya": "rider_priya", "rahul": "rider_rahul",
                "kumar": "driver_kumar", "fatima": "driver_fatima", "admin": "admin_ops"}
    uid = name_map.get(req.username.lower())
    if not uid or req.password != "password123":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    u = USERS[uid]
    token = u["token"].replace("Bearer ", "")
    return {"access_token": token, "token_type": "bearer",
            "user_id": uid, "name": u["name"], "role": u["role"]}

@app.get("/api/auth/me", tags=["Auth"])
def me(current_user=Depends(get_current_user)):
    safe = ["id", "name", "email", "role", "rating", "total_rides"]
    return {k: v for k, v in current_user.items() if k in safe}


# ── Riders (BOLA + BOPLA) ────────────────────────────────────────────────────

@app.get("/api/riders", tags=["Riders"])
def list_riders(current_user=Depends(get_current_user)):
    """⚠️ BFLA: Non-admin can list all riders with personal info."""
    return {"riders": [
        {"id": uid, "name": u["name"], "email": u["email"], "phone": u["phone"], "rating": u.get("rating")}
        for uid, u in USERS.items() if u["role"] == "RIDER"
    ]}

@app.get("/api/riders/{rider_id}", tags=["Riders"])
def get_rider(rider_id: str, current_user=Depends(get_current_user)):
    """⚠️ BOLA + BOPLA: Any user reads any rider's full profile including Aadhaar, home address, saved cards."""
    u = USERS.get(rider_id)
    if not u or u["role"] != "RIDER":
        raise HTTPException(status_code=404, detail="Rider not found")
    # ⚠️ No ownership check — returns EVERYTHING including Aadhaar & home address
    return u

@app.get("/api/riders/{rider_id}/trips", tags=["Riders"])
def get_rider_trips(rider_id: str, current_user=Depends(get_current_user)):
    """⚠️ BOLA: Any user can fetch full GPS trip history (home/work route patterns) of any rider."""
    if rider_id not in USERS or USERS[rider_id]["role"] != "RIDER":
        raise HTTPException(status_code=404, detail="Rider not found")
    # ⚠️ No ownership check
    rider_trips = [t for t in TRIPS.values() if t["rider_id"] == rider_id]
    return {"rider_id": rider_id, "rider_name": USERS[rider_id]["name"], "trips": rider_trips}

@app.get("/api/riders/{rider_id}/payment", tags=["Riders"])
def get_payment_methods(rider_id: str, current_user=Depends(get_current_user)):
    """⚠️ BOLA + BOPLA: Any user reads any rider's saved cards, UPI ID, and wallet balance."""
    u = USERS.get(rider_id)
    if not u or u["role"] != "RIDER":
        raise HTTPException(status_code=404, detail="Rider not found")
    # ⚠️ No ownership check
    return {
        "rider_id": rider_id, "name": u["name"],
        "saved_cards": u.get("saved_cards"),
        "upi_id": u.get("upi_id"),
        "account_balance": u.get("account_balance"),   # ⚠️ BOPLA
        "aadhaar_last4": u.get("aadhaar_last4"),        # ⚠️ BOPLA extremely sensitive
    }

@app.get("/api/riders/{rider_id}/location", tags=["Riders"])
def get_rider_live_location(rider_id: str, current_user=Depends(get_current_user)):
    """⚠️ BOLA: Exposes real-time GPS coordinates (home/work addresses inferred from patterns)."""
    u = USERS.get(rider_id)
    if not u or u["role"] != "RIDER":
        raise HTTPException(status_code=404, detail="Rider not found")
    # ⚠️ No ownership check — stalking risk
    return {
        "rider_id": rider_id, "name": u["name"],
        "current_location": u.get("home_address"),
        "home_address": u.get("home_address"),
        "work_address": u.get("work_address"),
    }

@app.delete("/api/riders/{rider_id}", tags=["Riders"])
def delete_rider(rider_id: str, current_user=Depends(get_current_user)):
    """⚠️ BFLA: Any user can delete any rider account."""
    if rider_id not in USERS:
        raise HTTPException(status_code=404, detail="Rider not found")
    USERS.pop(rider_id)
    return {"message": f"Rider {rider_id} deleted", "deleted_by": current_user["id"]}


# ── Drivers (BOLA + BOPLA) ───────────────────────────────────────────────────

@app.get("/api/drivers", tags=["Drivers"])
def list_drivers(current_user=Depends(get_current_user)):
    return {"drivers": [
        {"id": uid, "name": u["name"], "vehicle": u.get("vehicle"), "rating": u.get("rating")}
        for uid, u in USERS.items() if u["role"] == "DRIVER"
    ]}

@app.get("/api/drivers/{driver_id}", tags=["Drivers"])
def get_driver(driver_id: str, current_user=Depends(get_current_user)):
    """⚠️ BOLA + BOPLA: Returns Aadhaar number and bank account to any caller."""
    u = USERS.get(driver_id)
    if not u or u["role"] != "DRIVER":
        raise HTTPException(status_code=404, detail="Driver not found")
    # ⚠️ No ownership check — returns Aadhaar & bank account
    return u

@app.get("/api/drivers/{driver_id}/earnings", tags=["Drivers"])
def get_driver_earnings(driver_id: str, current_user=Depends(get_current_user)):
    """⚠️ BOLA: Any rider can see any driver's weekly/monthly income."""
    u = USERS.get(driver_id)
    if not u or u["role"] != "DRIVER":
        raise HTTPException(status_code=404, detail="Driver not found")
    # ⚠️ No ownership check
    return {
        "driver_id": driver_id, "name": u["name"],
        "weekly_earnings": u.get("weekly_earnings"),
        "monthly_earnings": u.get("monthly_earnings"),
        "bank_account": u.get("bank_account"),   # ⚠️ BOPLA
        "bank_ifsc": u.get("bank_ifsc"),
        "total_trips": u.get("total_trips"),
    }

@app.get("/api/drivers/{driver_id}/documents", tags=["Drivers"])
def get_driver_documents(driver_id: str, current_user=Depends(get_current_user)):
    """⚠️ BOLA: Any user can access any driver's government ID documents (Aadhaar, license, PCC)."""
    u = USERS.get(driver_id)
    if not u or u["role"] != "DRIVER":
        raise HTTPException(status_code=404, detail="Driver not found")
    # ⚠️ No ownership check
    docs = [d for d in DOCUMENTS.values() if d["owner_id"] == driver_id]
    return {"driver_id": driver_id, "name": u["name"], "documents": docs}


# ── Trips (BOLA) ─────────────────────────────────────────────────────────────

@app.get("/api/trips/{trip_id}", tags=["Trips"])
def get_trip(trip_id: str, current_user=Depends(get_current_user)):
    """⚠️ BOLA: Any user reads full trip details including GPS trace, rider notes, payment method."""
    trip = TRIPS.get(trip_id)
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    # ⚠️ No ownership check — full GPS trace + rider personal notes exposed
    return trip

@app.get("/api/trips", tags=["Trips"])
def list_all_trips(current_user=Depends(get_current_user)):
    """⚠️ BFLA: All trips from all users — should be admin-only."""
    return {"trips": list(TRIPS.values()), "total": len(TRIPS)}

@app.post("/api/trips/{trip_id}/rate", tags=["Trips"])
def rate_trip(trip_id: str, payload: dict, current_user=Depends(get_current_user)):
    """⚠️ BOLA: Any user can submit a rating for any trip they didn't take."""
    trip = TRIPS.get(trip_id)
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    trip["driver_rating_by_rider"] = payload.get("rating", 1)
    return {"message": "Rating submitted", "trip_id": trip_id, "rated_by": current_user["id"]}


# ── Admin (BFLA) ─────────────────────────────────────────────────────────────

@app.get("/api/admin/users", tags=["Admin"])
def admin_all_users(current_user=Depends(get_current_user)):
    """⚠️ BFLA: Dumps ALL user PII including bank accounts and Aadhaar — any user can call this."""
    return {"users": list(USERS.values()), "total": len(USERS), "extracted_by": current_user["id"]}

@app.get("/api/admin/reports/earnings", tags=["Admin"])
def admin_earnings_report(current_user=Depends(get_current_user)):
    """⚠️ BFLA: Complete financial report — accessible by any user."""
    return {
        "report": [{"driver_id": uid, "name": u["name"],
                    "weekly": u.get("weekly_earnings"), "monthly": u.get("monthly_earnings"),
                    "bank": u.get("bank_account")}
                   for uid, u in USERS.items() if u["role"] == "DRIVER"],
        "generated_by": current_user["id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/admin/surge", tags=["Admin"])
def get_surge(current_user=Depends(get_current_user)):
    """⚠️ BFLA: Surge pricing config — any user can read."""
    return SURGE_CONFIG

@app.post("/api/admin/surge", tags=["Admin"])
def update_surge(payload: dict, current_user=Depends(get_current_user)):
    """⚠️ BFLA: Any user can manipulate surge pricing — in Uber breach, attacker changed driver payouts."""
    city = payload.get("city", "delhi").lower()
    SURGE_CONFIG.setdefault(city, {})
    SURGE_CONFIG[city].update({k: v for k, v in payload.items() if k != "city"})
    return {"message": f"Surge updated for {city}", "config": SURGE_CONFIG[city], "updated_by": current_user["id"]}

@app.delete("/api/admin/users/{user_id}", tags=["Admin"])
def admin_delete_user(user_id: str, current_user=Depends(get_current_user)):
    """⚠️ BFLA: Any user can delete any account."""
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")
    USERS.pop(user_id)
    return {"message": f"User {user_id} deleted by {current_user['id']}"}


# ── Security Monitor API ─────────────────────────────────────────────────────

@app.get("/api/security/violations", tags=["Security Monitor"])
def get_violations(limit: int = 100):
    """Returns all detected unauthorized access violations in real-time."""
    vlist = list(VIOLATIONS)[:limit]
    counts = {"BOLA": 0, "BFLA": 0, "BOPLA": 0, "total": len(vlist)}
    attackers: Dict[str, int] = {}
    victims: Dict[str, int] = {}
    for v in vlist:
        vt = v["violation_type"]
        if vt in counts:
            counts[vt] += 1
        attackers[v["attacker_name"]] = attackers.get(v["attacker_name"], 0) + 1
        victims[v["victim_name"]] = victims.get(v["victim_name"], 0) + 1
    return {
        "violations": vlist,
        "summary": counts,
        "top_attackers": sorted(attackers.items(), key=lambda x: -x[1]),
        "top_victims": sorted(victims.items(), key=lambda x: -x[1]),
    }

@app.post("/api/security/reset", tags=["Security Monitor"])
def reset_violations():
    """Clear all violation logs."""
    VIOLATIONS.clear()
    return {"message": "Violation log cleared"}


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
def dashboard():
    """Serve the live breach monitoring dashboard."""
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>dashboard.html not found. Place it alongside main.py</h1>", status_code=404)
