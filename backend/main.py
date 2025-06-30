import os
import logging
import json
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SOC Dashboard API",
    description="API for SOC dashboard and alert management",
    version="1.0.0"
)

# Allow React frontend to call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory data stores for prototype
alerts: List[Dict] = [
    {
        "id": "alert-001",
        "type": "Risky Sign-In",
        "severity": "High",
        "status": "Open",
        "assigned_to": "Analyst 1",
        "timestamp": "2024-01-15T10:30:00Z",
        "description": "Unusual login pattern detected from new location"
    },
    {
        "id": "alert-002", 
        "type": "Risky Sign-In",
        "severity": "Medium",
        "status": "In Progress",
        "assigned_to": "Analyst 2",
        "timestamp": "2024-01-15T09:15:00Z",
        "description": "Multiple failed login attempts followed by successful login"
    }
]

playbooks: Dict[str, List[Dict]] = {
    "alert-001": [
        {
            "id": "step-1",
            "description": "Verify user identity",
            "checked": False,
            "automated": True,
            "approval_required": True,
            "timestamp": None,
            "analyst": None,
            "approved": None
        },
        {
            "id": "step-2", 
            "description": "Check for suspicious activity",
            "checked": False,
            "automated": False,
            "approval_required": False,
            "timestamp": None,
            "analyst": None,
            "approved": None
        }
    ]
}

audit_logs = []

# Models
class PlaybookStep(BaseModel):
    id: str
    description: str
    checked: bool = False
    automated: bool = False
    approval_required: bool = False
    timestamp: Optional[str] = None
    analyst: Optional[str] = None
    approved: Optional[bool] = None

class Alert(BaseModel):
    id: str
    type: str
    severity: str
    status: str
    assigned_to: str
    timestamp: str
    description: str

class PlaybookUpdate(BaseModel):
    step_id: str
    checked: bool
    analyst: str

class ApprovalAction(BaseModel):
    step_id: str
    approved: bool
    analyst: str

# SOC Dashboard Endpoints
@app.get("/alerts/risky-signin", response_model=List[Alert])
def get_risky_signin_alerts():
    return [a for a in alerts if a["type"] == "Risky Sign-In"]

@app.get("/playbook/risky-signin/{alert_id}", response_model=List[PlaybookStep])
def get_playbook(alert_id: str):
    if alert_id not in playbooks:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbooks[alert_id]

@app.post("/playbook/risky-signin/{alert_id}")
def update_playbook(alert_id: str, update: PlaybookUpdate):
    if alert_id not in playbooks:
        raise HTTPException(status_code=404, detail="Playbook not found")
    steps = playbooks[alert_id]
    for step in steps:
        if step["id"] == update.step_id:
            step["checked"] = update.checked
            step["timestamp"] = datetime.utcnow().isoformat()
            step["analyst"] = update.analyst
            break
    return {"success": True}

@app.post("/playbook/risky-signin/{alert_id}/approve")
def approve_automated_step(alert_id: str, action: ApprovalAction):
    if alert_id not in playbooks:
        raise HTTPException(status_code=404, detail="Playbook not found")
    steps = playbooks[alert_id]
    for step in steps:
        if step["id"] == action.step_id and step["automated"] and step["approval_required"]:
            step["approved"] = action.approved
            step["timestamp"] = datetime.utcnow().isoformat()
            step["analyst"] = action.analyst
            audit_logs.append({
                "alert_id": alert_id,
                "step_id": action.step_id,
                "approved": action.approved,
                "analyst": action.analyst,
                "timestamp": step["timestamp"]
            })
            break
    return {"success": True}

@app.post("/automation/verify-user")
def automation_verify_user(alert_id: str = Body(...), step_id: str = Body(...)):
    # Simulate sending a verification prompt
    return {"success": True, "message": f"Verification prompt sent for alert {alert_id}, step {step_id}"}

@app.get("/dashboard/metrics")
def dashboard_metrics():
    total_alerts = len(alerts)
    open_alerts = len([a for a in alerts if a["status"] == "Open"])
    in_progress = len([a for a in alerts if a["status"] == "In Progress"])
    overdue = len([a for a in alerts if a["status"] == "Overdue"])
    
    return {
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "in_progress": in_progress,
        "overdue": overdue
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 