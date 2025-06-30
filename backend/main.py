import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from dotenv import load_dotenv
import openai

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

class RuleRequest(BaseModel):
    threat_description: str
    platforms: List[str]

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
            rule = response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"Error generating rule for {platform}: {e}")
            rule = f"Error generating rule: {e}"
        rules[platform] = rule
    return {"rules": rules} 