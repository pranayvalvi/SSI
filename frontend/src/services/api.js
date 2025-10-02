import axios from 'axios';
import { getStoredToken, removeStoredToken } from '../utils/storage';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:4000',
  timeout: parseInt(process.env.REACT_APP_API_TIMEOUT) || 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = getStoredToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle auth errors
api.interceptors.response.use(
  (response) => {
    return response.data;
  },
  (error) => {
    // Handle 401 errors (unauthorized)
    if (error.response?.status === 401) {
      removeStoredToken();
      window.location.href = '/login';
    }
    
    // Return structured error response
    return Promise.reject({
      message: error.response?.data?.error?.message || error.message,
      status: error.response?.status,
      code: error.response?.data?.error?.code,
      response: error.response,
    });
  }
);

// Authentication API
export const authAPI = {
  register: (userData) => api.post('/api/auth/register', userData),
  login: (credentials) => api.post('/api/auth/login', credentials),
  logout: () => api.post('/api/auth/logout'),
  getProfile: () => api.get('/api/auth/profile'),
  updateProfile: (profileData) => api.put('/api/auth/profile', profileData),
  changePassword: (passwordData) => api.put('/api/auth/change-password', passwordData),
  verifyToken: () => api.get('/api/auth/verify-token'),
};

// Issuer API
export const issuerAPI = {
  register: (issuerData) => api.post('/api/issuers/register', issuerData),
  update: (id, issuerData) => api.put(`/api/issuers/${id}`, issuerData),
  confirmRegistration: (id, txData) => api.post(`/api/issuers/${id}/confirm-registration`, txData),
  getAll: (params = {}) => api.get('/api/issuers', { params }),
  getById: (id) => api.get(`/api/issuers/${id}`),
  getMyProfile: () => api.get('/api/issuers/my/profile'),
};

// Credential API
export const credentialAPI = {
  issue: (credentialData) => api.post('/api/credentials/issue', credentialData),
  revoke: (id, revokeData) => api.post(`/api/credentials/${id}/revoke`, revokeData),
  getAll: (params = {}) => api.get('/api/credentials', { params }),
  getById: (id) => api.get(`/api/credentials/${id}`),
  verify: (verificationData) => api.post('/api/credentials/verify', verificationData),
};

// Verification API
export const verificationAPI = {
  createChallenge: (challengeData) => api.post('/api/verification/challenge', challengeData),
  verifyPresentation: (presentationData) => api.post('/api/verification/presentation', presentationData),
  batchVerify: (credentialsData) => api.post('/api/verification/batch', credentialsData),
  getStatus: (hash) => api.get(`/api/verification/status/${hash}`),
  getIssuerStatus: (address) => api.get(`/api/verification/issuer/${address}`),
};

// Health check
export const healthAPI = {
  check: () => api.get('/health'),
};

// Generic API helpers
export const apiHelpers = {
  // Upload file (if needed for future features)
  uploadFile: (file, endpoint) => {
    const formData = new FormData();
    formData.append('file', file);
    
    return api.post(endpoint, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },
  
  // Download file
  downloadFile: async (url, filename) => {
    try {
      const response = await api.get(url, {
        responseType: 'blob',
      });
      
      const blob = new Blob([response.data]);
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(downloadUrl);
    } catch (error) {
      console.error('Download failed:', error);
      throw error;
    }
  },
  
  // Retry failed requests
  retryRequest: async (requestFn, maxRetries = 3, delay = 1000) => {
    let lastError;
    
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await requestFn();
      } catch (error) {
        lastError = error;
        if (i < maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
        }
      }
    }
    
    throw lastError;
  },
};

export default api;
