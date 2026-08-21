import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api/v1';

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 5000,
});

export const triggerIncident = async (incidentData) => {
  try {
    const response = await client.post('/incident/trigger', incidentData);
    return response.data;
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
};

export const checkHealth = async () => {
  try {
    const response = await axios.get('http://localhost:8000/health', { timeout: 3000 });
    return response.data;
  } catch (error) {
    console.error('Health check failed:', error);
    throw error;
  }
};