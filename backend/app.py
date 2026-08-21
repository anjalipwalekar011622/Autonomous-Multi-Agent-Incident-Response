from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import Config

app = FastAPI(
    title="Autonomous Multi-Agent Incident Response API",
    version="1.0.0"
)

# Enable CORS for frontend connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production origin
    allow_credentials=True,
    allow_methods=["*"],  # Allows GET, POST, OPTIONS, etc.
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "online", "system": "Incident Response Engine"}

# Placeholder endpoint for Member 3's Orchestrator execution
@app.post("/api/v1/incident/trigger")
async def trigger_incident_response(payload: dict):
    # This will invoke orchestrator/workflow.py in integration phase
    return {"message": "Incident investigation initiated", "incident_id": "INC-001"}