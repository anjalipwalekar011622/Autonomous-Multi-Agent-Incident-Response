import datetime
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from backend.config import Config
from orchestrator.workflow import build_workflow
from orchestrator.state import empty_incident_state
from langgraph.types import Command

app = FastAPI(title="Incident Response API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

class IncidentRequest(BaseModel):
    type: str = "Manual Trigger"
    target: str = "Host-01"

# Initialize global workflow to share memory saver
workflow = build_workflow()

@app.post("/api/incidents/trigger")
@app.post("/api/v1/incident/trigger")
async def trigger_incident(payload: IncidentRequest):
    try:
        initial_state = empty_incident_state()
        
        # Generate a unique incident_id to use as thread_id
        incident_id = f"INC-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        initial_state["incident_id"] = incident_id
        
        config = {"configurable": {"thread_id": incident_id}}
        
        # Execute workflow up to interrupt (or completion)
        result_state = workflow.invoke(initial_state, config=config)
        
        # In case invoke returns None during interrupt, fallback to get_state
        if result_state is None:
            current = workflow.get_state(config)
            result_state = current.values
            
        return {
            "status": "success",
            "incident_id": incident_id,
            "state": result_state,
            "details": payload
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/incidents/{incident_id}/approve")
async def approve_incident(incident_id: str):
    try:
        config = {"configurable": {"thread_id": incident_id}}
        
        # Resume the paused workflow with APPROVED
        result_state = workflow.invoke(Command(resume="APPROVED"), config=config)
        
        if result_state is None:
            current = workflow.get_state(config)
            result_state = current.values
            
        return {
            "status": "success",
            "incident_id": incident_id,
            "state": result_state
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/incidents/{incident_id}/reject")
async def reject_incident(incident_id: str):
    try:
        config = {"configurable": {"thread_id": incident_id}}
        
        # Resume the paused workflow with REJECTED
        result_state = workflow.invoke(Command(resume="REJECTED"), config=config)
        
        if result_state is None:
            current = workflow.get_state(config)
            result_state = current.values
            
        return {
            "status": "success",
            "incident_id": incident_id,
            "state": result_state
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host=Config.HOST, port=Config.PORT, reload=Config.DEBUG)
    uvicorn.run("backend.main:app", host=Config.HOST, port=Config.PORT, reload=Config.DEBUG)