import os
import logging
import json
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
from dotenv import load_dotenv
import openai
from datetime import datetime
import uuid

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
print('OPENAI_API_KEY:', os.getenv('OPENAI_API_KEY'))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Detection Rule Canvas API",
    description="API for generating detection rules using AI",
    version="1.0.0"
)

# Allow Streamlit frontend to call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'rule_history.json')

# In-memory data stores for prototype
alerts = []
playbooks = {}
audit_logs = []

# Models
class PlaybookStep(BaseModel):
    id: str
    description: str
    checked: bool = False
    automated: bool = False
    approval_required: bool = False
    approved: Optional[bool] = None
    timestamp: Optional[str] = None
    analyst: Optional[str] = None

class Alert(BaseModel):
    id: str
    type: str
    status: str
    assigned_to: Optional[str] = None
    created_at: str
    updated_at: str

class PlaybookUpdate(BaseModel):
    step_id: str
    checked: bool
    analyst: str

class ApprovalAction(BaseModel):
    step_id: str
    approved: bool
    analyst: str

class RuleRequest(BaseModel):
    threat_description: str
    platforms: List[str]

class AnalyzeRequest(BaseModel):
    rule: str
    platform: str

class MitreRequest(BaseModel):
    rule: str

class SimulateRequest(BaseModel):
    rule: str
    log_sample: str

class HistoryRequest(BaseModel):
    rule_id: str
    rule: str
    platform: str

# Helper to generate a sample alert and playbook
if not alerts:
    alert_id = str(uuid.uuid4())
    alerts.append(Alert(
        id=alert_id,
        type="Risky Sign-In",
        status="open",
        assigned_to=None,
        created_at=datetime.utcnow().isoformat(),
        updated_at=datetime.utcnow().isoformat()
    ))
    playbooks[alert_id] = [
        PlaybookStep(id="1", description="Validate alert details", checked=False),
        PlaybookStep(id="2", description="Check user activity", checked=False),
        PlaybookStep(id="3", description="Enrich with threat intel", checked=False),
        PlaybookStep(id="4", description="Contact user for verification", checked=False, automated=True, approval_required=True),
        PlaybookStep(id="5", description="Containment: Disable account or require password reset", checked=False, automated=True, approval_required=True),
        PlaybookStep(id="6", description="Document findings", checked=False),
    ]

@app.post("/generate")
async def generate_rules(request: RuleRequest):
    openai.api_key = os.getenv("OPENAI_API_KEY")
    if not openai.api_key:
        logger.error("OpenAI API key not set.")
        raise HTTPException(status_code=500, detail="OpenAI API key not set.")
    rules = {}
    for platform in request.platforms:
        prompt = (
            f"Generate a detection rule for the following threat for {platform}:\n\n"
            f"{request.threat_description}\n\nRule:"
        )
        try:
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an expert detection engineer."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=400,
                temperature=0.4,
            )
            rule = (response.choices[0].message.content or '').strip()
            # Save to history
            save_rule_to_history(request.threat_description, platform, rule)
        except Exception as e:
            logger.error(f"Error generating rule for {platform}: {e}")
            rule = f"Error generating rule: {e}"
        rules[platform] = rule
    return {"rules": rules}

@app.post("/extract")
async def extract_threat_intel(file: UploadFile = File(...)):
    openai.api_key = os.getenv("OPENAI_API_KEY")
    content = await file.read()
    # For MVP, treat all as text
    text = content.decode(errors="ignore")
    prompt = f"Extract all IOCs, TTPs, and relevant context from the following threat intel. Summarize clearly for detection engineering.\n\n{text}\n\nSummary:"
    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an expert threat intelligence analyst."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=400,
            temperature=0.3,
        )
        summary = (response.choices[0].message.content or '').strip()
        return {"summary": summary}
    except Exception as e:
        logger.error(f"Error extracting threat intel: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze")
async def analyze_rule(request: AnalyzeRequest):
    openai.api_key = os.getenv("OPENAI_API_KEY")
    prompt = f"Review the following detection rule for {request.platform}. Score it 1-10 for quality, coverage, and clarity. Give feedback and suggestions.\n\nRule:\n{request.rule}\n\nAnalysis:"
    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a senior detection engineer and rule reviewer."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=400,
            temperature=0.3,
        )
        analysis = (response.choices[0].message.content or '').strip()
        return {"analysis": analysis}
    except Exception as e:
        logger.error(f"Error analyzing rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/mitre_tags")
async def mitre_tags(request: MitreRequest):
    openai.api_key = os.getenv("OPENAI_API_KEY")
    prompt = f"Suggest the most relevant MITRE ATT&CK techniques and tactics for this detection rule.\n\nRule:\n{request.rule}\n\nList the ATT&CK IDs and names."
    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a MITRE ATT&CK mapping expert."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.2,
        )
        tags = (response.choices[0].message.content or '').strip()
        return {"mitre_tags": tags}
    except Exception as e:
        logger.error(f"Error suggesting MITRE tags: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/simulate")
async def simulate_rule(request: SimulateRequest):
    # MVP: simple substring match
    try:
        match = request.rule.lower() in request.log_sample.lower()
        return {"match": match}
    except Exception as e:
        logger.error(f"Error simulating rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/history")
async def rule_history(request: HistoryRequest):
    # Return all versions for a rule_id (threat_description+platform for MVP)
    rule_id = f"{request.rule_id}_{request.platform}"
    history = load_rule_history()
    versions = history.get(rule_id, [])
    return {"versions": versions}

@app.get("/export")
async def export_rule(rule: str = '', platform: str = 'Sigma'):
    # Save rule to a temp file and return as download
    filename = f"exported_{platform.lower()}_rule.txt"
    filepath = os.path.join(os.path.dirname(__file__), filename)
    with open(filepath, 'w') as f:
        f.write(rule)
    return FileResponse(filepath, filename=filename, media_type='text/plain')

@app.get("/alerts/risky-signin", response_model=List[Alert])
def get_risky_signin_alerts():
    return [a for a in alerts if a.type == "Risky Sign-In"]

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
        if step.id == update.step_id:
            step.checked = update.checked
            step.timestamp = datetime.utcnow().isoformat()
            step.analyst = update.analyst
            break
    return {"success": True}

@app.post("/playbook/risky-signin/{alert_id}/approve")
def approve_automated_step(alert_id: str, action: ApprovalAction):
    if alert_id not in playbooks:
        raise HTTPException(status_code=404, detail="Playbook not found")
    steps = playbooks[alert_id]
    for step in steps:
        if step.id == action.step_id and step.automated and step.approval_required:
            step.approved = action.approved
            step.timestamp = datetime.utcnow().isoformat()
            step.analyst = action.analyst
            audit_logs.append({
                "alert_id": alert_id,
                "step_id": action.step_id,
                "approved": action.approved,
                "analyst": action.analyst,
                "timestamp": step.timestamp
            })
            break
    return {"success": True}

@app.post("/automation/verify-user")
def automation_verify_user(alert_id: str = Body(...), step_id: str = Body(...)):
    # Simulate sending a verification prompt
    return {"success": True, "message": f"Verification prompt sent for alert {alert_id}, step {step_id}"}

@app.get("/dashboard/metrics")
def dashboard_metrics():
    total = len(alerts)
    open_alerts = len([a for a in alerts if a.status == "open"])
    in_progress = len([a for a in alerts if a.status == "in_progress"])
    overdue = 0  # For prototype, not implemented
    return {
        "total": total,
        "open": open_alerts,
        "in_progress": in_progress,
        "overdue": overdue
    }

# --- Helper functions for rule history ---
def save_rule_to_history(threat_description, platform, rule):
    threat_description = (threat_description or '').strip()
    platform = (platform or '').strip()
    rule_id = f"{threat_description}_{platform}"
    history = load_rule_history()
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "rule": rule
    }
    if rule_id not in history:
        history[rule_id] = []
    history[rule_id].append(entry)
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def load_rule_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    with open(HISTORY_FILE, 'r') as f:
        return json.load(f) 