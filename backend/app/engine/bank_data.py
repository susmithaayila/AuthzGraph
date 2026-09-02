"""
SecureBank Demo — Synthetic Fake Dataset
100% Synthetic, Locally Generated Data for Security Demonstration.
No real users, no real APIs, no real financial data.
"""
from typing import Dict, List, Any
import copy

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Users (15 users to demonstrate multi-user data exposure and access control)
# ─────────────────────────────────────────────────────────────────────────────
INITIAL_SYNTHETIC_USERS: Dict[int, Dict[str, Any]] = {
    101: {
        "id": 101,
        "name": "Alice Johnson",
        "email": "alice.johnson@securebank.local",
        "phone": "+1-555-0101",
        "role": "CUSTOMER",
        "department": "Retail Banking",
        "region": "South",
        "clearance": "CONFIDENTIAL",
        "clearance_level": 3,
        "accountBalance": 75000.00,
        "isVerified": True,
        "internalRiskScore": 12,
        "token": "token_alice",
        "address": "742 Evergreen Terrace, Springfield, OR",
        "aadhaar_last4": "8812",
        "account_id": "ACC-101",
    },
    102: {
        "id": 102,
        "name": "Bob Smith",
        "email": "bob.smith@securebank.local",
        "phone": "+1-555-0102",
        "role": "CUSTOMER",
        "department": "Retail Banking",
        "region": "North",
        "clearance": "CONFIDENTIAL",
        "clearance_level": 3,
        "accountBalance": 142500.50,
        "isVerified": True,
        "internalRiskScore": 45,
        "token": "token_bob",
        "address": "123 Elm Street, Metropolis, NY",
        "aadhaar_last4": "3391",
        "account_id": "ACC-102",
    },
    103: {
        "id": 103,
        "name": "Charlie Davis",
        "email": "charlie.davis@securebank.local",
        "phone": "+1-555-0103",
        "role": "CUSTOMER",
        "department": "Retail Banking",
        "region": "South",
        "clearance": "INTERNAL",
        "clearance_level": 2,
        "accountBalance": 18200.00,
        "isVerified": False,
        "internalRiskScore": 78,
        "token": "token_charlie",
        "address": "456 Oak Ave, Gotham, NJ",
        "aadhaar_last4": "9921",
        "account_id": "ACC-103",
    },
    104: {
        "id": 104,
        "name": "David Miller",
        "email": "david.miller@securebank.local",
        "phone": "+1-555-0104",
        "role": "CUSTOMER",
        "department": "Wealth Management",
        "region": "East",
        "clearance": "CONFIDENTIAL",
        "clearance_level": 3,
        "accountBalance": 980000.00,
        "isVerified": True,
        "internalRiskScore": 5,
        "token": "token_david",
        "address": "789 Pine St, Star City, CA",
        "aadhaar_last4": "1104",
        "account_id": "ACC-104",
    },
    105: {
        "id": 105,
        "name": "Eva Martinez",
        "email": "eva.martinez@securebank.local",
        "phone": "+1-555-0105",
        "role": "CUSTOMER",
        "department": "Retail Banking",
        "region": "West",
        "clearance": "INTERNAL",
        "clearance_level": 2,
        "accountBalance": 34500.75,
        "isVerified": True,
        "internalRiskScore": 22,
        "token": "token_eva",
        "address": "321 Maple Rd, Central City, MO",
        "aadhaar_last4": "5505",
        "account_id": "ACC-105",
    },
    106: {
        "id": 106,
        "name": "Frank Wright",
        "email": "frank.wright@securebank.local",
        "phone": "+1-555-0106",
        "role": "CUSTOMER",
        "department": "Commercial Banking",
        "region": "North",
        "clearance": "CONFIDENTIAL",
        "clearance_level": 3,
        "accountBalance": 520000.00,
        "isVerified": True,
        "internalRiskScore": 18,
        "token": "token_frank",
        "address": "654 Birch Blvd, Coast City, CA",
        "aadhaar_last4": "7706",
        "account_id": "ACC-106",
    },
    107: {
        "id": 107,
        "name": "Grace Lee",
        "email": "grace.lee@securebank.local",
        "phone": "+1-555-0107",
        "role": "CUSTOMER",
        "department": "Retail Banking",
        "region": "South",
        "clearance": "INTERNAL",
        "clearance_level": 2,
        "accountBalance": 8900.00,
        "isVerified": True,
        "internalRiskScore": 8,
        "token": "token_grace",
        "address": "987 Cedar Ln, Blüdhaven, NJ",
        "aadhaar_last4": "4407",
        "account_id": "ACC-107",
    },
    108: {
        "id": 108,
        "name": "Henry Wilson",
        "email": "henry.wilson@securebank.local",
        "phone": "+1-555-0108",
        "role": "CUSTOMER",
        "department": "Retail Banking",
        "region": "East",
        "clearance": "PUBLIC",
        "clearance_level": 1,
        "accountBalance": 1200.00,
        "isVerified": False,
        "internalRiskScore": 92,
        "token": "token_henry",
        "address": "159 Walnut Ct, Keystone City, KS",
        "aadhaar_last4": "8808",
        "account_id": "ACC-108",
    },
    109: {
        "id": 109,
        "name": "Isabel Taylor",
        "email": "isabel.taylor@securebank.local",
        "phone": "+1-555-0109",
        "role": "CUSTOMER",
        "department": "Retail Banking",
        "region": "North",
        "clearance": "CONFIDENTIAL",
        "clearance_level": 3,
        "accountBalance": 64000.00,
        "isVerified": True,
        "internalRiskScore": 14,
        "token": "token_isabel",
        "address": "753 Chestnut Dr, Hub City, IL",
        "aadhaar_last4": "9909",
        "account_id": "ACC-109",
    },
    110: {
        "id": 110,
        "name": "Jack Anderson",
        "email": "jack.anderson@securebank.local",
        "phone": "+1-555-0110",
        "role": "CUSTOMER",
        "department": "Retail Banking",
        "region": "West",
        "clearance": "CONFIDENTIAL",
        "clearance_level": 3,
        "accountBalance": 210000.00,
        "isVerified": True,
        "internalRiskScore": 30,
        "token": "token_jack",
        "address": "852 Spruce Way, Midway City, MI",
        "aadhaar_last4": "1210",
        "account_id": "ACC-110",
    },
    201: {
        "id": 201,
        "name": "Sarah Jenkins (Support Agent)",
        "email": "sarah.support@securebank.local",
        "phone": "+1-555-0201",
        "role": "SUPPORT",
        "department": "Customer Support",
        "region": "South",
        "clearance": "INTERNAL",
        "clearance_level": 2,
        "accountBalance": 0.0,
        "isVerified": True,
        "internalRiskScore": 0,
        "token": "token_support",
        "address": "Support HQ, Floor 2",
        "aadhaar_last4": "0001",
        "account_id": "STAFF-201",
    },
    301: {
        "id": 301,
        "name": "Marcus Vance (Regional Manager)",
        "email": "marcus.vance@securebank.local",
        "phone": "+1-555-0301",
        "role": "MANAGER",
        "department": "Retail Banking",
        "region": "South",
        "clearance": "CONFIDENTIAL",
        "clearance_level": 3,
        "accountBalance": 0.0,
        "isVerified": True,
        "internalRiskScore": 0,
        "token": "token_manager",
        "address": "Executive Suites, Floor 4",
        "aadhaar_last4": "0002",
        "account_id": "STAFF-301",
    },
    302: {
        "id": 302,
        "name": "Diana Park (North Regional Manager)",
        "email": "diana.park@securebank.local",
        "phone": "+1-555-0302",
        "role": "MANAGER",
        "department": "Retail Banking",
        "region": "North",
        "clearance": "CONFIDENTIAL",
        "clearance_level": 3,
        "accountBalance": 0.0,
        "isVerified": True,
        "internalRiskScore": 0,
        "token": "token_manager_north",
        "address": "North Branch Executive Office, Floor 5",
        "aadhaar_last4": "0003",
        "account_id": "STAFF-302",
    },
    401: {
        "id": 401,
        "name": "Dr. Aris Thorne (Security Admin)",
        "email": "admin.security@securebank.local",
        "phone": "+1-555-0401",
        "role": "ADMIN",
        "department": "IT Security",
        "region": "Global",
        "clearance": "SECRET",
        "clearance_level": 4,
        "accountBalance": 0.0,
        "isVerified": True,
        "internalRiskScore": 0,
        "token": "token_admin",
        "address": "Security Operations Center, Floor 10",
        "aadhaar_last4": "9999",
        "account_id": "STAFF-401",
    },
}

# Token to User mapping for quick authentication simulation
TOKEN_MAP: Dict[str, Dict[str, Any]] = {
    user["token"]: user for user in INITIAL_SYNTHETIC_USERS.values()
}
# Also support bare tokens e.g. "token_alice" or "Bearer token_alice"
for user in list(INITIAL_SYNTHETIC_USERS.values()):
    TOKEN_MAP[f"Bearer {user['token']}"] = user
    TOKEN_MAP[user["token"].replace("token_", "")] = user



# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Accounts & Transactions
# ─────────────────────────────────────────────────────────────────────────────
SYNTHETIC_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    f"ACC-{user_id}": {
        "id": f"ACC-{user_id}",
        "user_id": user_id,
        "account_number": f"SB-8829-{user_id:04d}",
        "account_type": "PREMIUM CHECKING" if user_id in (101, 104, 106, 110) else "SAVINGS",
        "balance": INITIAL_SYNTHETIC_USERS[user_id]["accountBalance"],
        "currency": "USD",
        "created_at": "2024-01-15T10:00:00Z",
    }
    for user_id in INITIAL_SYNTHETIC_USERS if INITIAL_SYNTHETIC_USERS[user_id]["role"] == "CUSTOMER"
}


SYNTHETIC_TRANSACTIONS: Dict[int, List[Dict[str, Any]]] = {
    101: [
        {"id": "TX-101-1", "user_id": 101, "amount": -125.50, "description": "Grocery Mart", "date": "2026-08-28T14:20:00Z", "type": "DEBIT"},
        {"id": "TX-101-2", "user_id": 101, "amount": 3500.00, "description": "Payroll Direct Deposit", "date": "2026-08-25T09:00:00Z", "type": "CREDIT"},
        {"id": "TX-101-3", "user_id": 101, "amount": -45.00, "description": "Electric Utility", "date": "2026-08-22T18:11:00Z", "type": "DEBIT"},
    ],
    102: [
        {"id": "TX-102-1", "user_id": 102, "amount": -890.00, "description": "Luxury Hotel Booking", "date": "2026-08-29T11:05:00Z", "type": "DEBIT"},
        {"id": "TX-102-2", "user_id": 102, "amount": 7200.00, "description": "Consulting Fee Transfer", "date": "2026-08-26T16:30:00Z", "type": "CREDIT"},
        {"id": "TX-102-3", "user_id": 102, "amount": -320.00, "description": "Airline Ticket Upgrade", "date": "2026-08-21T08:45:00Z", "type": "DEBIT"},
    ],
    103: [
        {"id": "TX-103-1", "user_id": 103, "amount": -55.00, "description": "Gas Station", "date": "2026-08-27T19:00:00Z", "type": "DEBIT"},
    ],
    104: [
        {"id": "TX-104-1", "user_id": 104, "amount": 25000.00, "description": "Investment Yield Dividend", "date": "2026-08-29T15:00:00Z", "type": "CREDIT"},
    ]
}


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Documents (for ABAC & MAC demonstrations)
# ─────────────────────────────────────────────────────────────────────────────
SYNTHETIC_DOCUMENTS: Dict[int, Dict[str, Any]] = {
    501: {
        "id": 501,
        "owner_id": 101,
        "title": "Alice_Tax_Return_2025.pdf",
        "department": "Retail Banking",
        "region": "South",
        "classification": "CONFIDENTIAL",
        "classification_level": 3,
        "summary": "Annual confidential personal tax documentation for Alice Johnson.",
    },
    502: {
        "id": 502,
        "owner_id": 102,
        "title": "Bob_Loan_Agreement_Confidential.pdf",
        "department": "Retail Banking",
        "region": "North",
        "classification": "CONFIDENTIAL",
        "classification_level": 3,
        "summary": "Private commercial credit line agreement for Bob Smith.",
    },
    503: {
        "id": 503,
        "owner_id": 301,
        "title": "South_Region_Salary_Audit_Report.pdf",
        "department": "Retail Banking",
        "region": "South",
        "classification": "CONFIDENTIAL",
        "classification_level": 3,
        "summary": "Internal salary and compensation evaluation for South Region employees.",
    },
    504: {
        "id": 504,
        "owner_id": 401,
        "title": "Bank_Master_HSM_Key_Rotation_Policy.pdf",
        "department": "IT Security",
        "region": "Global",
        "classification": "SECRET",
        "classification_level": 4,
        "summary": "Top secret infrastructure key management standard operating procedures.",
    },
    505: {
        "id": 505,
        "owner_id": 101,
        "title": "Public_Branch_Operating_Hours.pdf",
        "department": "Retail Banking",
        "region": "South",
        "classification": "PUBLIC",
        "classification_level": 1,
        "summary": "Publicly accessible customer branch timetable.",
    },
    506: {
        # ABAC test: Owned by South-region manager (301), scoped to SOUTH region.
        # A North-region MANAGER (302) has correct RBAC (AUDIT_READ) but fails ABAC region check.
        # Used to prove ABAC_CROSS_REGION violation is isolated from BOLA ownership.
        "id": 506,
        "owner_id": 301,
        "title": "South_Region_Compliance_Audit_Q3_2026.pdf",
        "department": "Retail Banking",
        "region": "South",
        "classification": "CONFIDENTIAL",
        "classification_level": 3,
        "summary": "Quarterly compliance and risk audit report for the South regional branch.",
    },
    507: {
        # MAC write-down test: A PUBLIC document owned by admin.
        # A SECRET-clearance user (ADMIN, 401) attempting to downgrade its classification
        # to PUBLIC triggers the Bell-LaPadula star-property (No Write Down) check.
        "id": 507,
        "owner_id": 401,
        "title": "IT_Security_Incident_Postmortem_Draft.pdf",
        "department": "IT Security",
        "region": "Global",
        "classification": "SECRET",
        "classification_level": 4,
        "summary": "Draft post-mortem for a recent IT Security incident. Classification must not be downgraded without CISO approval.",
    },
    508: {
        # MAC No-Read-Up test: Owned by Alice herself (101), scoped to Retail Banking / South.
        # RBAC, BOLA (owner match), and ABAC all pass cleanly.
        # Only Alice's CONFIDENTIAL clearance (Level 3) vs. SECRET classification (Level 4) blocks access.
        "id": 508,
        "owner_id": 101,
        "title": "Alice_Secret_Financial_Vault.pdf",
        "department": "Retail Banking",
        "region": "South",
        "classification": "SECRET",
        "classification_level": 4,
        "summary": "Top secret personal financial vault document owned by Alice Johnson.",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Support Tickets
# ─────────────────────────────────────────────────────────────────────────────
SYNTHETIC_TICKETS: Dict[int, Dict[str, Any]] = {
    701: {
        "id": 701,
        "owner_id": 101,
        "assigned_department": "Customer Support",
        "region": "South",
        "subject": "Disputed Card Charge of $45.00",
        "status": "OPEN",
        "priority": "HIGH",
        "description": "Alice reporting an unrecognized recurring charge on utility bill.",
    },
    702: {
        "id": 702,
        "owner_id": 102,
        "assigned_department": "Customer Support",
        "region": "North",
        "subject": "Wire Transfer Limit Increase Request",
        "status": "IN_PROGRESS",
        "priority": "MEDIUM",
        "description": "Bob requesting international wire allowance upgrade for property purchase.",
    },
    703: {
        "id": 703,
        "owner_id": 103,
        "assigned_department": "Retail Banking",
        "region": "South",
        "subject": "KYC Document Re-verification",
        "status": "RESOLVED",
        "priority": "LOW",
        "description": "Charlie submitted updated proof of residence.",
    },
}

SYNTHETIC_USERS: Dict[int, Dict[str, Any]] = copy.deepcopy(INITIAL_SYNTHETIC_USERS)


def reset_synthetic_data():
    global SYNTHETIC_USERS, TOKEN_MAP
    SYNTHETIC_USERS.clear()
    SYNTHETIC_USERS.update(copy.deepcopy(INITIAL_SYNTHETIC_USERS))
    TOKEN_MAP.clear()
    for user in SYNTHETIC_USERS.values():
        TOKEN_MAP[user["token"]] = user
        TOKEN_MAP[f"Bearer {user['token']}"] = user
        TOKEN_MAP[user["token"].replace("token_", "")] = user

