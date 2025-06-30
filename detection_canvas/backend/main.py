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

