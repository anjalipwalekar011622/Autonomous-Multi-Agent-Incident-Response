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

import threading
import time
from agents.threat_hunter.log_parser import LogParser
from agents.threat_hunter.threat_hunter import ThreatHunterAgent

monitor_running = False
monitor_thread = None
log_parser = LogParser()

# Initialize global workflow to share memory saver
workflow = build_workflow()

# Track active thread IDs in-memory for the reporting dashboard
thread_ids = []

@app.get("/api/incidents")
async def get_all_incidents():
    try:
        incidents = []
        # Return newest first
        for t_id in reversed(thread_ids):
            config = {"configurable": {"thread_id": t_id}}
            current = workflow.get_state(config)
            if current and current.values:
                incidents.append(current.values)
        return {"status": "success", "incidents": incidents}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def _monitor_and_trigger():
    global monitor_running
    agent = ThreatHunterAgent()
    agent.parser = log_parser # share the parser
    
    while monitor_running:
        try:
            alerts = agent.run_detection()
            if alerts:
                # We found an alert! Trigger workflow automatically
                initial_state = empty_incident_state()
                initial_state["event"]["raw_data"] = {"pre_detected_alerts": alerts}
                incident_id = f"INC-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}"
                initial_state["incident_id"] = incident_id
                config = {"configurable": {"thread_id": incident_id}}
                thread_ids.append(incident_id)
                workflow.invoke(initial_state, config=config)
        except Exception as e:
            print(f"[Monitor] error: {e}")
        time.sleep(5)

@app.post("/api/monitoring/start")
async def start_monitoring():
    global monitor_running, monitor_thread
    if monitor_running:
        return {"status": "success", "message": "Monitoring is already running"}
    
    # Start the consumer loop
    monitor_running = True
    monitor_thread = threading.Thread(target=_monitor_and_trigger, daemon=True)
    monitor_thread.start()
    return {"status": "success", "message": "Monitoring started"}

@app.post("/api/monitoring/stop")
async def stop_monitoring():
    global monitor_running
    monitor_running = False
    return {"status": "success", "message": "Monitoring stopped"}



@app.post("/api/incidents/trigger")
@app.post("/api/v1/incident/trigger")
async def trigger_incident(payload: IncidentRequest):
    try:
        initial_state = empty_incident_state()
        
        # Generate a unique incident_id to use as thread_id
        incident_id = f"INC-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        initial_state["incident_id"] = incident_id
        
        config = {"configurable": {"thread_id": incident_id}}
        
        if incident_id not in thread_ids:
            thread_ids.append(incident_id)
            
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