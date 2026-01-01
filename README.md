"""
ABAC Policy Engine
Single-file FastAPI application

Features:
- Attribute-Based Access Control (ABAC)
- Dynamic policy rules
- Decoupled authorization engine
- SQLite persistence
- Production-grade access control design

Run:
pip install fastapi uvicorn
uvicorn app:app --reload
"""

import sqlite3
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ABAC Policy Engine")
DB_PATH = "policies.db"

# -------------------------
# Database
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            effect TEXT,
            subject_attr TEXT,
            resource_attr TEXT,
            action TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

def get_db():
    return sqlite3.connect(DB_PATH)

# -------------------------
# Models
# -------------------------
class PolicyCreate(BaseModel):
    name: str
    effect: str            # allow / deny
    subject_attr: str      # e.g. role=admin
    resource_attr: str     # e.g. owner=self
    action: str            # e.g. read

class AccessRequest(BaseModel):
    subject: Dict[str, Any]
    resource: Dict[str, Any]
    action: str

# -------------------------
# Policy Evaluation Engine
# -------------------------
def match_attributes(attributes: Dict[str, Any], rule: str) -> bool:
    key, expected = rule.split("=")
    return str(attributes.get(key)) == expected

def evaluate_policies(request: AccessRequest) -> bool:
    conn = get_db()
    cur = conn.cursor()

    policies = cur.execute(
        "SELECT effect, subject_attr, resource_attr, action FROM policies"
    ).fetchall()

    conn.close()

    for effect, s_attr, r_attr, action in policies:
        if action != request.action:
            continue

        if not match_attributes(request.subject, s_attr):
            continue

        if not match_attributes(request.resource, r_attr):
            continue

        return effect == "allow"

    return False

# -------------------------
# API Routes
# -------------------------
@app.post("/policies")
def create_policy(policy: PolicyCreate):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO policies (name, effect, subject_attr, resource_attr, action) VALUES (?, ?, ?, ?, ?)",
            (
                policy.name,
                policy.effect,
                policy.subject_attr,
                policy.resource_attr,
                policy.action
            )
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Policy already exists")
    finally:
        conn.close()

    return {"status": "policy_created"}

@app.post("/authorize")
def authorize(request: AccessRequest):
    decision = evaluate_policies(request)
    return {
        "decision": "ALLOW" if decision else "DENY"
    }

@app.get("/policies")
def list_policies():
    conn = get_db()
    cur = conn.cursor()

    rows = cur.execute(
        "SELECT name, effect, subject_attr, resource_attr, action FROM policies"
    ).fetchall()

    conn.close()

    return [
        {
            "name": r[0],
            "effect": r[1],
            "subject_rule": r[2],
            "resource_rule": r[3],
            "action": r[4]
        }
        for r in rows
    ]
