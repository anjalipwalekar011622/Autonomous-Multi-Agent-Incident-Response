import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from backend.config import Config

# 1. Initialize FastAPI app once at the top
app = FastAPI(title="Incident Response API")

# 2. Add CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# 3. Define Request Model
class IncidentRequest(BaseModel):
    type: str = "Manual Trigger"
    target: str = "Host-01"

# 4. Define Endpoint
@app.post("/api/v1/incident/trigger")
async def trigger_incident(payload: IncidentRequest):
    return {
        "status": "success",
        "incident_id": "INC-9042",
        "details": payload
    }

# 5. Entry point
if __name__ == "__main__":
    uvicorn.run("backend.main:app", host=Config.HOST, port=Config.PORT, reload=Config.DEBUG)