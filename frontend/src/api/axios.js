import axios from 'axios';

// Base API configuration
// In production (Render), relative URL '' is used because Flask serves both frontend static files and /api endpoints.
// In local development, use Vite proxy (relative path) to avoid CORS issues with session cookies.
const getBaseUrl = () => {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  // Always use relative path in browser context to leverage Vite proxy
  // Vite proxy forwards /api/* to http://127.0.0.1:5000/api/*
  if (typeof window !== 'undefined') {
    return ''; // Relative path - uses Vite proxy in development
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
