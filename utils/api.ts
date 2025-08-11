// API Utility for PSB Fraud Shield
// Handles all server communication with proper error handling

import { secureApiService } from './apiSecurity';
import { SECURITY_CONFIG } from './securityConfig';

export const API_BASE_URL =
  process.env.SERVER_URL || (__DEV__ ? 'http://localhost:5000/api' : SECURITY_CONFIG.API.BASE_URL);

if (!__DEV__ && !API_BASE_URL.startsWith('https://')) {
  throw new Error('Plain HTTP is blocked in production');
}

// Ensure secure client uses the same base URL origin
try {
  const resolved = process.env.SERVER_URL || SECURITY_CONFIG.API.BASE_URL;
  if (resolved) {
    secureApiService.updateBaseURL(resolved);
  }
} catch {}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  profile: {
    level: string;
    experiencePoints: number;
    badges: string[];
    achievements: string[];
  };
  analytics: {
    simulationsCompleted: number;
    fraudDetected: number;
    learningProgress: number;
  };
}

export interface SimulationResult {
  id: string;
  type: string;
  score: number;
  timeSpent: number;
  redFlagsDetected: string[];
  completedAt: Date;
}

export interface FraudReport {
  id: string;
  type: string;
  details: {
    description: string;
    evidence: string[];
    severity: string;
  };
  status: string;
  createdAt: Date;
}

// Generic API call function (now backed by secure client)
export const apiCall = async <T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> => {
  try {
    const method = (options.method || 'GET').toUpperCase();
    const headers = options.headers as Record<string, string> | undefined;
    const body = options.body as any;

    let responseData: any;

    if (method === 'GET') {
      responseData = await secureApiService.secureGet<T>(endpoint, { headers });
    } else if (method === 'POST') {
      responseData = await secureApiService.securePost<T>(endpoint, body, { headers });
    } else if (method === 'PUT') {
      responseData = await secureApiService.securePut<T>(endpoint, body, { headers });
    } else if (method === 'DELETE') {
      responseData = await secureApiService.secureDelete<T>(endpoint, { headers });
    } else {
      // Fallback: try as POST
      responseData = await secureApiService.securePost<T>(endpoint, body, { headers });
    }

    return {
      success: true,
      data: responseData,
    };
  } catch (error: any) {
    console.error('API call failed:', error);
    return {
      success: false,
      error: error?.message || 'Network error. Please check your connection.',
    };
  }
};

// Document Hash Verification
export const verifyDocumentHash = async (
  documentHash: string,
  originalHash: string
): Promise<ApiResponse<{ isValid: boolean; confidence: number }>> => {
  return apiCall('/verify-document-hash', {
    method: 'POST',
    body: JSON.stringify({ documentHash, originalHash }),
  });
};

// URL Phishing Analysis
export const analyzeUrl = async (
  url: string,
  userId?: string
): Promise<ApiResponse<{
  isPhishing: boolean;
  confidence: number;
  redFlags: string[];
  recommendations: string[];
}>> => {
  return apiCall('/analyze-url', {
    method: 'POST',
    body: JSON.stringify({ url, userId }),
  });
};

// User Analytics
export const getUserAnalytics = async (userId: string): Promise<ApiResponse<User>> => {
  return apiCall(`/user-analytics/${userId}`);
};

export const trackActivity = async (
  userId: string,
  activity: {
    type: string;
    details: any;
    timestamp: Date;
  }
): Promise<ApiResponse> => {
  return apiCall('/track-activity', {
    method: 'POST',
    body: JSON.stringify({ userId, ...activity }),
  });
};

// Simulation Results
export const saveSimulationResult = async (
  userId: string,
  result: Omit<SimulationResult, 'id' | 'completedAt'>
): Promise<ApiResponse<SimulationResult>> => {
  return apiCall('/simulation-results', {
    method: 'POST',
    body: JSON.stringify({ userId, ...result }),
  });
};

export const getSimulationResults = async (
  userId: string
): Promise<ApiResponse<SimulationResult[]>> => {
  return apiCall(`/simulation-results/${userId}`);
};

// Fraud Reports
export const submitFraudReport = async (
  userId: string,
  report: Omit<FraudReport, 'id' | 'createdAt'>
): Promise<ApiResponse<FraudReport>> => {
  return apiCall('/fraud-reports', {
    method: 'POST',
    body: JSON.stringify({ userId, ...report }),
  });
};

export const getFraudReports = async (
  userId: string
): Promise<ApiResponse<FraudReport[]>> => {
  return apiCall(`/fraud-reports/${userId}`);
};

// Nearest Cybercell Finder
export const findNearestCybercell = async (
  latitude: number,
  longitude: number
): Promise<ApiResponse<{
  name: string;
  address: string;
  distance: number;
  contact: string;
}[]>> => {
  return apiCall('/nearest-cybercell', {
    method: 'POST',
    body: JSON.stringify({ latitude, longitude }),
  });
};

// Scam Heat Map Data
export const getScamHeatMapData = async (
  region?: string
): Promise<ApiResponse<{
  locations: Array<{
    latitude: number;
    longitude: number;
    intensity: number;
    type: string;
    reportedAt: Date;
  }>;
}>> => {
  const params = region ? `?region=${encodeURIComponent(region)}` : '';
  return apiCall(`/scam-heat-map${params}`);
};

// Health Check
export const checkServerHealth = async (): Promise<ApiResponse<{ status: string }>> => {
  return apiCall('/health');
};

// OTP Functions
export const sendSMSOTP = async (
  phoneNumber: string,
  purpose: string = "verification"
): Promise<ApiResponse<{ message: string; purpose: string; expiresIn: string }>> => {
  return apiCall('/send-otp-sms', {
    method: 'POST',
    body: JSON.stringify({ phoneNumber, purpose }),
  });
};

export const sendEmailOTP = async (
  email: string,
  purpose: string = "verification"
): Promise<ApiResponse<{ message: string; purpose: string; expiresIn: string }>> => {
  return apiCall('/send-otp-email', {
    method: 'POST',
    body: JSON.stringify({ email, purpose }),
  });
};

export const verifyOTP = async (
  identifier: string,
  otp: string,
  type: string = "sms"
): Promise<ApiResponse<{ message: string; verified: boolean }>> => {
  return apiCall('/verify-otp', {
    method: 'POST',
    body: JSON.stringify({ identifier, otp, type }),
  });
};

export const resendOTP = async (
  identifier: string,
  type: string = "sms"
): Promise<ApiResponse<{ message: string; expiresIn: string }>> => {
  return apiCall('/resend-otp', {
    method: 'POST',
    body: JSON.stringify({ identifier, type }),
  });
};

export const getOTPStatus = async (
  identifier: string
): Promise<ApiResponse<{
  exists: boolean;
  expired: boolean;
  remainingTime: number;
  attempts: number;
  type: string;
}>> => {
  return apiCall(`/otp-status/${identifier}`);
};

// Enhanced Authentication with OTP
export const sendSignupOTP = async (
  email?: string,
  phone?: string
): Promise<ApiResponse<{ message: string; expiresIn: string }>> => {
  return apiCall('/auth/send-signup-otp', {
    method: 'POST',
    body: JSON.stringify({ email, phone }),
  });
};

export const signupWithOTP = async (
  userData: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    phone?: string;
    otp: string;
    identifier: string;
  }
): Promise<ApiResponse<{ token: string; user: User; message: string }>> => {
  return apiCall('/auth/signup-with-otp', {
    method: 'POST',
    body: JSON.stringify(userData),
  });
};

export const sendLoginOTP = async (
  email: string,
  password: string
): Promise<ApiResponse<{ message: string; expiresIn: string }>> => {
  return apiCall('/auth/send-login-otp', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
};

export const loginWithOTP = async (
  email: string,
  password: string,
  otp: string,
  identifier: string
): Promise<ApiResponse<{ token: string; user: User; message: string }>> => {
  return apiCall('/auth/login-with-otp', {
    method: 'POST',
    body: JSON.stringify({ email, password, otp, identifier }),
  });
};

export const forgotPasswordOTP = async (
  email: string
): Promise<ApiResponse<{ message: string; expiresIn: string }>> => {
  return apiCall('/auth/forgot-password-otp', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
};

export const resetPasswordOTP = async (
  email: string,
  otp: string,
  identifier: string,
  newPassword: string
): Promise<ApiResponse<{ message: string }>> => {
  return apiCall('/auth/reset-password-otp', {
    method: 'POST',
    body: JSON.stringify({ email, otp, identifier, newPassword }),
  });
};

// Error handling utilities
export const handleApiError = (error: string, fallbackMessage = 'Something went wrong') => {
  console.error('API Error:', error);
  
  // You can integrate with your error reporting service here
  // Example: Sentry.captureException(new Error(error));
  
  return error || fallbackMessage;
};

// Retry mechanism for critical operations
export const apiCallWithRetry = async <T>(
  endpoint: string,
  options: RequestInit = {},
  maxRetries: number = 3
): Promise<ApiResponse<T>> => {
  let lastError: string = '';
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const result = await apiCall<T>(endpoint, options);
    
    if (result.success) {
      return result;
    }
    
    lastError = result.error || 'Unknown error';
    
    // Wait before retrying (exponential backoff)
    if (attempt < maxRetries) {
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
    }
  }
  
  return {
    success: false,
    error: `Failed after ${maxRetries} attempts. Last error: ${lastError}`,
  };
};

// Offline support utilities
export const isOnline = (): boolean => {
  return navigator.onLine !== false;
};

export const queueOfflineRequest = (request: {
  endpoint: string;
  options: RequestInit;
  timestamp: number;
}) => {
  // Store request in local storage for later processing
  const offlineQueue = JSON.parse(localStorage.getItem('offlineQueue') || '[]');
  offlineQueue.push(request);
  localStorage.setItem('offlineQueue', JSON.stringify(offlineQueue));
};

export const processOfflineQueue = async () => {
  if (!isOnline()) return;
  
  const offlineQueue = JSON.parse(localStorage.getItem('offlineQueue') || '[]');
  
  for (const request of offlineQueue) {
    try {
      await apiCall(request.endpoint, request.options);
    } catch (error) {
      console.error('Failed to process offline request:', error);
    }
  }
  
  localStorage.removeItem('offlineQueue');
};

// Export all API functions
export default {
  verifyDocumentHash,
  analyzeUrl,
  getUserAnalytics,
  trackActivity,
  saveSimulationResult,
  getSimulationResults,
  submitFraudReport,
  getFraudReports,
  findNearestCybercell,
  getScamHeatMapData,
  checkServerHealth,
  sendSMSOTP,
  sendEmailOTP,
  verifyOTP,
  resendOTP,
  getOTPStatus,
  sendSignupOTP,
  signupWithOTP,
  sendLoginOTP,
  loginWithOTP,
  forgotPasswordOTP,
  resetPasswordOTP,
  handleApiError,
  apiCallWithRetry,
  isOnline,
  queueOfflineRequest,
  processOfflineQueue,
};