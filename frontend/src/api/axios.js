import axios from 'axios';

// Base API configuration
// In production (Render), relative URL '' is used because Flask serves both frontend static files and /api endpoints.
// In local development (localhost), fallback to 'http://127.0.0.1:5000'.
const getBaseUrl = () => {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  if (typeof window !== 'undefined') {
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      return 'http://127.0.0.1:5000';
    }
    return ''; // Production: relative path
  }
  return '';
};

const apiClient = axios.create({
  baseURL: getBaseUrl(),
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

export default apiClient;
