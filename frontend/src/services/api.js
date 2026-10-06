import axios from 'axios';

// Get base URL for deployment, Codespaces, or Localhost
const getBaseUrl = () => {
  // If we set a VITE_API_URL in deployment (e.g. Vercel/Netlify), use it
  if (import.meta.env && import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }

  const host = window.location.hostname;
  if (host.includes('app.github.dev')) {
    const backendHost = host.replace(/-\d+\.app\.github\.dev/, '-8000.app.github.dev');
    return `https://${backendHost}`;
  }
  return 'http://127.0.0.1:8000';
};

const BASE_URL = getBaseUrl();

const client = axios.create({
  baseURL: `${BASE_URL}/api/v1/incident`,
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
    const response = await fetch(`${BASE_URL}/api/incidents`);
    return await response.json();
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
};