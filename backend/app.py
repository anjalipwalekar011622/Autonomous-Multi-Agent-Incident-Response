from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from backend.config import Config

app = FastAPI(
    title="Autonomous Multi-Agent Incident Response API",
    version="1.0.0"
)

# Fix: Set allow_credentials to False when using wildcard origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class IncidentRequest(BaseModel):
    type: str = "Manual Trigger"
    target: str = "Host-01"

@app.get("/health")
def health_check():
    return {"status": "online", "system": "Incident Response Engine"}

@app.post("/api/v1/incident/trigger")
async def trigger_incident_response(payload: IncidentRequest):
    return {
        "status": "success",
        "message": "Incident investigation initiated", 
        "incident_id": "INC-9042",
        "details": payload
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=Config.HOST, port=Config.PORT, reload=Config.DEBUG)