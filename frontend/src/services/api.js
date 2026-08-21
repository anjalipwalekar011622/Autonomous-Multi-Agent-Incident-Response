import axios from 'axios';


// Align path with FastAPI endpoint
const rawBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const BASE = rawBase.replace(/\/+$/, ''); 
const API_BASE_URL = `${BASE}/api/v1/incident`; // Added /incident here

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 5000,
});

export const triggerIncident = async (incidentData) => {
  try {
    const response = await client.post('/trigger', incidentData);
    return response.data;
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
};


export const checkHealth = async () => {
  try {
    const response = await axios.get('/health', { timeout: 3000 });
    return response.data;
  } catch (error) {
    console.error('Health check failed:', error);
    throw error;
  }
};