from orchestrator.workflow import build_workflow
from orchestrator.mock_data import MOCK_INCIDENT_STATE

app = build_workflow()
result = app.invoke(MOCK_INCIDENT_STATE)

print("\n=== FINAL STATE ===")
print("Execution Result:", result.get("execution_result"))
print("Final Status:", result.get("status"))