import axios from 'axios';

// Detects Codespaces environment dynamically and points to Port 8000
const getBaseUrl = () => {
  const host = window.location.hostname;
  if (host.includes('app.github.dev')) {
    // Replaces -5176 (or any frontend port) with -8000
    const backendHost = host.replace(/-\d+\.app\.github\.dev/, '-8000.app.github.dev');
    return `https://${backendHost}/api/v1/incident`;
  }
  return 'http://127.0.0.1:8000/api/v1/incident';
};

const client = axios.create({
  baseURL: getBaseUrl(),
  timeout: 60000,
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

export const getIncidents = async () => {
  try {
    const response = await fetch('http://127.0.0.1:8000/api/incidents');
    return await response.json();
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
};