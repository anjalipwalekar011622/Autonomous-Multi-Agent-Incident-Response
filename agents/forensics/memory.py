import chromadb
from typing import Dict, Any, List

class IncidentMemory:
    def __init__(self, db_path: str = "./chroma_db"):
        # Creates/connects to a local persistent ChromaDB database on disk
        self.client = chromadb.PersistentClient(path=db_path)
        # Creates or retrieves a vector collection for security incidents
        self.collection = self.client.get_or_create_collection(
            name="forensic_incident_memory"
        )

    def store_incident(self, incident_id: str, summary: str, metadata: Dict[str, Any]):
        """
        Saves an incident's summary and metadata into ChromaDB vector storage.
        """
        self.collection.add(
            documents=[summary],
            metadatas=[metadata],
            ids=[incident_id]
        )
        print(f"[Memory] Stored Incident '{incident_id}' into ChromaDB memory.")

    def query_similar_incidents(self, current_anomaly_text: str, top_k: int = 2) -> Dict[str, Any]:
        """
        Queries ChromaDB to find historically similar attacks based on vector distance.
        """
        results = self.collection.query(
            query_texts=[current_anomaly_text],
            n_results=top_k
        )
        return results