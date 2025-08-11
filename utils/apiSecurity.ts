import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import * as Crypto from 'expo-crypto';
import { SECURITY_CONFIG, getSecurityHeaders } from './securityConfig';
import { encryptionService } from './encryption';
import * as CryptoJS from 'crypto-js';

export interface SecureApiConfig {
  baseURL: string;
  timeout: number;
  enableSSL: boolean;
  enableEncryption: boolean;
  enableRateLimit: boolean;
}

export class SecureApiService {
  private static instance: SecureApiService;
  private apiClient: AxiosInstance;
  private requestCount: Map<string, number> = new Map();
  private lastRequestTime: Map<string, number> = new Map();

  private constructor() {
    this.apiClient = axios.create({
      baseURL: SECURITY_CONFIG.API.BASE_URL,
      timeout: SECURITY_CONFIG.API.TIMEOUT,
      headers: getSecurityHeaders(),
    });

    this.setupInterceptors();
  }

  public static getInstance(): SecureApiService {
    if (!SecureApiService.instance) {
      SecureApiService.instance = new SecureApiService();
    }
    return SecureApiService.instance;
  }

  // Setup request and response interceptors
  private setupInterceptors(): void {
    // Request interceptor
    this.apiClient.interceptors.request.use(
      async (config) => {
        // Add security headers
        const hdrs: Record<string, any> = {
          ...(config.headers as any),
          ...getSecurityHeaders(),
          'X-Request-ID': await this.generateRequestId(),
          'X-Timestamp': Date.now().toString(),
        };

        // Rate limiting check
        if (SECURITY_CONFIG.API.RATE_LIMIT.ENABLED) {
          await this.checkRateLimit(config.url || '');
        }

        // Encrypt request data only with shared secret
        const sharedSecret = SECURITY_CONFIG.API.ENCRYPTION.SHARED_SECRET || process.env.API_SHARED_SECRET;
        if (SECURITY_CONFIG.API.ENCRYPTION.ENABLED && sharedSecret && config.data) {
          const { payload, ivBase64 } = await this.encryptWithSharedSecret(
            typeof config.data === 'string' ? config.data : JSON.stringify(config.data),
            sharedSecret
          );
          hdrs['X-Encrypted'] = '1';
          hdrs['X-IV'] = ivBase64;
          hdrs['Content-Type'] = 'text/plain';
          config.data = payload;
        }

        config.headers = hdrs as any;
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.apiClient.interceptors.response.use(
      async (response) => {
        // Decrypt response data only when header is present and shared secret configured
        const sharedSecret = SECURITY_CONFIG.API.ENCRYPTION.SHARED_SECRET || process.env.API_SHARED_SECRET;
        const isEncrypted = !!(response.headers && ((response.headers['x-encrypted'] as any) === '1' || (response.headers['X-Encrypted'] as any) === '1'));
        const ivHeader = (response.headers && ((response.headers['x-iv'] as any) || (response.headers['X-IV'] as any))) as string | undefined;

        if (SECURITY_CONFIG.API.ENCRYPTION.ENABLED && sharedSecret && isEncrypted && typeof response.data === 'string') {
          response.data = await this.decryptWithSharedSecret(response.data, sharedSecret, ivHeader);
        }

        // Verify response integrity if header present
        if (response.headers['x-response-hash']) {
          const isValid = await this.verifyResponseIntegrity(response);
          if (!isValid) {
            throw new Error('Response integrity check failed');
          }
        }

        return response;
      },
      async (error) => {
        // Handle SSL pinning errors
        if (error.code === 'CERTIFICATE_VERIFY_FAILED') {
          throw new Error('SSL certificate verification failed');
        }

        // Handle rate limit errors
        if (error.response?.status === 429) {
          throw new Error('Rate limit exceeded');
        }

        return Promise.reject(error);
      }
    );
  }

  // Shared-secret AES-256-CBC helpers
  private async encryptWithSharedSecret(plaintext: string, secret: string): Promise<{ payload: string; ivBase64: string }> {
    const ivWordArray = CryptoJS.lib.WordArray.random(16);
    const keyWordArray = CryptoJS.SHA256(secret);
    const cipherParams = CryptoJS.AES.encrypt(plaintext, keyWordArray, {
      iv: ivWordArray,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    const payload = cipherParams.ciphertext.toString(CryptoJS.enc.Base64);
    const ivBase64 = CryptoJS.enc.Base64.stringify(ivWordArray);
    return { payload, ivBase64 };
  }

  private async decryptWithSharedSecret(ciphertextBase64: string, secret: string, ivBase64?: string): Promise<any> {
    if (!ivBase64) throw new Error('Missing IV for shared-secret decryption');
    const keyWordArray = CryptoJS.SHA256(secret);
    const ivWordArray = CryptoJS.enc.Base64.parse(ivBase64);
    const decrypted = CryptoJS.AES.decrypt({ ciphertext: CryptoJS.enc.Base64.parse(ciphertextBase64) } as any, keyWordArray, {
      iv: ivWordArray,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    const text = CryptoJS.enc.Utf8.stringify(decrypted);
    try {
      return JSON.parse(text);
    } catch {
      return text as any;
    }
  }

  // Generate unique request ID
  private async generateRequestId(): Promise<string> {
    const randomBytes = await Crypto.getRandomBytesAsync(16);
    return Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      randomBytes.toString() + Date.now().toString(),
      { encoding: Crypto.CryptoEncoding.BASE64 }
    );
  }

  // Rate limiting implementation
  private async checkRateLimit(url: string): Promise<void> {
    const now = Date.now();
    const key = this.getRateLimitKey(url);
    
    // Clean old entries
    if (this.lastRequestTime.has(key)) {
      const lastTime = this.lastRequestTime.get(key) || 0;
      if (now - lastTime > 60000) { // 1 minute
        this.requestCount.delete(key);
        this.lastRequestTime.delete(key);
      }
    }

    // Check current count
    const currentCount = this.requestCount.get(key) || 0;
    if (currentCount >= SECURITY_CONFIG.API.RATE_LIMIT.REQUESTS_PER_MINUTE) {
      throw new Error('Rate limit exceeded');
    }

    // Update counters
    this.requestCount.set(key, currentCount + 1);
    this.lastRequestTime.set(key, now);
  }

  private getRateLimitKey(url: string): string {
    // Extract endpoint from URL for rate limiting
    const endpoint = url.split('?')[0].split('/').pop() || 'default';
    return endpoint;
  }

  // Encrypt request data
  private async encryptRequestData(data: any): Promise<string> {
    const jsonString = JSON.stringify(data);
    return await encryptionService.encrypt(jsonString);
  }

  // Decrypt response data
  private async decryptResponseData(encryptedData: string): Promise<any> {
    const decryptedString = await encryptionService.decrypt(encryptedData);
    return JSON.parse(decryptedString);
  }

  // Verify response integrity
  private async verifyResponseIntegrity(response: AxiosResponse): Promise<boolean> {
    const expectedHash = response.headers['x-response-hash'];
    const responseData = JSON.stringify(response.data);
    const actualHash = await encryptionService.generateHash(responseData);
    return actualHash === expectedHash;
  }

  // Secure GET request
  public async secureGet<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.apiClient.get<T>(url, config);
      return response.data;
    } catch (error) {
      throw this.handleApiError(error);
    }
  }

  // Secure POST request
  public async securePost<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.apiClient.post<T>(url, data, config);
      return response.data;
    } catch (error) {
      throw this.handleApiError(error);
    }
  }

  // Secure PUT request
  public async securePut<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.apiClient.put<T>(url, data, config);
      return response.data;
    } catch (error) {
      throw this.handleApiError(error);
    }
  }

  // Secure DELETE request
  public async secureDelete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.apiClient.delete<T>(url, config);
      return response.data;
    } catch (error) {
      throw this.handleApiError(error);
    }
  }

  // Handle API errors
  private handleApiError(error: any): Error {
    if (error.response) {
      // Server responded with error status
      const status = error.response.status;
      const message = error.response.data?.message || 'API request failed';
      
      switch (status) {
        case 401:
          return new Error('Authentication required');
        case 403:
          return new Error('Access forbidden');
        case 404:
          return new Error('Resource not found');
        case 429:
          return new Error('Rate limit exceeded');
        case 500:
          return new Error('Internal server error');
        default:
          return new Error(`API error: ${status} - ${message}`);
      }
    } else if (error.request) {
      // Network error
      return new Error('Network connection failed');
    } else {
      // Other error
      return new Error(error.message || 'Unknown error occurred');
    }
  }

  // Set authentication token
  public setAuthToken(token: string): void {
    this.apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  // Clear authentication token
  public clearAuthToken(): void {
    delete this.apiClient.defaults.headers.common['Authorization'];
  }

  // Update base URL
  public updateBaseURL(baseURL: string): void {
    this.apiClient.defaults.baseURL = baseURL;
  }

  // Get current API client
  public getApiClient(): AxiosInstance {
    return this.apiClient;
  }
}

// Export singleton instance
export const secureApiService = SecureApiService.getInstance();

// Utility functions for common API operations
export const secureGet = async <T>(url: string, config?: AxiosRequestConfig): Promise<T> => {
  return await secureApiService.secureGet<T>(url, config);
};

export const securePost = async <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> => {
  return await secureApiService.securePost<T>(url, data, config);
};

export const securePut = async <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> => {
  return await secureApiService.securePut<T>(url, data, config);
};

export const secureDelete = async <T>(url: string, config?: AxiosRequestConfig): Promise<T> => {
  return await secureApiService.secureDelete<T>(url, config);
};

export const setAuthToken = (token: string): void => {
  secureApiService.setAuthToken(token);
};

export const clearAuthToken = (): void => {
  secureApiService.clearAuthToken();
};
