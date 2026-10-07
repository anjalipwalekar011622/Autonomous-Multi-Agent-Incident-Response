# Autonomous Multi-Agent Incident Response - Deployment Guide

## 1. Prerequisites
- **Operating System:** Windows 10/11 or Windows Server (Native execution on isolated VM recommended for testing).
- **Python:** Python 3.10+ (Tested with 3.11). Must be added to system `PATH`.
- **Node.js:** Node.js v18+ and `npm`.
- **(Optional) Sysmon:** For real-time advanced telemetry (Process Creation, Process Access, Registry, etc.). If unavailable, mock telemetry fixtures will run.
- **(Optional) Ollama:** To power dynamic LLM MITRE ATT&CK mapping via local models on port `11434`. If unavailable, a static dictionary fallback is gracefully used.

## 2. Configuration & Secrets
Create a `.env` file in the root directory by copying the example.
```bash
cp .env.example .env
```
*Note: The project is designed to run securely without external API keys if using local components.*

### ChromaDB Storage
ChromaDB uses a portable, project-relative local storage path defined internally. Ensure the `chroma_db/` folder has read/write permissions for the user running the backend. No external vector database container is required.

## 3. Dependency Installation
### Backend (Python)
From the project root:
```powershell
python -m venv venv
.\venv\Scripts\activate
python -m pip install -r requirements.txt
```

### Frontend (Node.js)
```powershell
cd frontend
npm install
```

## 4. Startup Instructions
**Start Backend (FastAPI)**
In a new PowerShell window (run as Administrator if testing active mitigations like IP blocking):
```powershell
$env:PYTHONPATH="."
python backend/main.py
```
*API will run at http://127.0.0.1:8000*

**Start Frontend (React / Vite)**
In a new PowerShell window:
```powershell
cd frontend
npm run dev
```
*Dashboard will run at http://localhost:5173*

## 5. Monitoring (Start/Stop)
Once both servers are running:
1. Open the React Dashboard.
2. Click **"Start Auto-Monitor"** to launch the background telemetry worker. 
3. The backend guarantees only a single continuous thread monitors system logs without duplicate polling.
4. Click **"Stop Monitoring"** to halt telemetry ingestion.

## 6. Safe Testing Procedure
This repository is configured out-of-the-box to use safe synthetic indicators if real attacks are not present.
1. Run `$env:PYTHONPATH="."; python tests/test_workflow.py` to validate core LangGraph functionality.
2. In the UI, synthetic telemetry will spawn incidents automatically while monitoring is ON.
3. Review the "Alerts" tab for detected events (e.g., Suspicious PowerShell).
4. **Approve** a mitigation. 
   - If running as a standard user, execution will safely `FAIL` due to lack of privileges.
   - If running as Admin on synthetic processes, it will safely `FAIL` due to process/IP non-existence.
   - The workflow will securely record this in the Verification block.

## 7. Troubleshooting
- **Missing Module `lucide-react` in Frontend:** Run `rm -r node_modules; npm install` in the frontend directory to do a clean install.
- **Ollama Refused Connection:** This is normal if Ollama is not installed. Forensics will log `[Forensics Agent] Reverting to static dictionary` and proceed.
- **CORS Error:** Verify the backend is running and `fastapi[all]` is properly installed.

## 8. VM Deployment Notes
When transferring this project to an isolated VM:
1. Copy the repository via shared folder or secure SCP. Do not clone via Git if the VM lacks internet access.
2. Ensure you have offline installers for Python, Node, and wheel dependencies if the VM is strictly air-gapped.
3. Run the backend as Administrator ONLY if you want to allow the Mitigation agent to physically block ports or terminate processes.

## 9. Security & Safety Limitations
- **NO DESTRUCTIVE ACTIONS:** The codebase natively refuses to delete critical system processes (`csrss.exe`, `lsass.exe`, `smss.exe`, `svchost.exe`).
- **NO CREDENTIAL DUMPING:** Telemetry only monitors for LSASS *access*, it does not execute dumping.
- **ISOLATED SANDBOX PREFERRED:** Always run incident response tests in a sandbox or VM.
