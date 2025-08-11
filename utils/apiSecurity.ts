import 'react-native-get-random-values';
import {fetch as rnFetch} from 'react-native-ssl-pinning';
import type { AxiosRequestConfig, AxiosResponse } from 'axios';
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
  private baseURL: string;
  private defaultTimeout: number;
  private authToken?: string;
  private requestCount: Map<string, number> = new Map();
  private lastRequestTime: Map<string, number> = new Map();

  private constructor() {
    this.baseURL = SECURITY_CONFIG.API.BASE_URL;
    this.defaultTimeout = SECURITY_CONFIG.API.TIMEOUT;
  }

  public static getInstance(): SecureApiService {
    if (!SecureApiService.instance) {
      SecureApiService.instance = new SecureApiService();
    }
    return SecureApiService.instance;
  }

  private async prepareRequest(config: AxiosRequestConfig): Promise<AxiosRequestConfig> {
    // Add security headers
    const hdrs: Record<string, any> = {
      ...(config.headers as any),
      ...getSecurityHeaders(),
      'X-Request-ID': await this.generateRequestId(),
      'X-Timestamp': Date.now().toString(),
    };

    if (this.authToken) {
      hdrs['Authorization'] = `Bearer ${this.authToken}`;
    }

    // Rate limiting check
    if (SECURITY_CONFIG.API.RATE_LIMIT.ENABLED) {
      await this.checkRateLimit(config.url || '');
    }

    // Transport encryption ONLY when shared secret is set
    // Transport encryption ONLY when shared secret is set
    const sharedSecret =
      SECURITY_CONFIG.API.ENCRYPTION.SHARED_SECRET || process.env.API_SHARED_SECRET;
    console.log('[TX] sharedSecret=', sharedSecret);

    if (SECURITY_CONFIG.API.ENCRYPTION.ENABLED && sharedSecret) {
      // Always request encrypted responses
      hdrs['X-Encrypted'] = '1';

      if (config.data) {
        // Encrypt request body when present (POST/PUT)
        const { payload, ivBase64 } = await this.encryptWithSharedSecret(
          typeof config.data === 'string' ? config.data : JSON.stringify(config.data),
          sharedSecret
        );
        hdrs['X-IV'] = ivBase64;
        hdrs['Content-Type'] = 'text/plain';
        config.data = payload;

        console.log(
          '[TX] encrypted=1',
          'iv.len=', ivBase64?.length,
          'ctype=', hdrs['Content-Type'],
          'body.sample=', String(config.data).slice(0, 60)
        );
      } else {
        // GET/DELETE: no body, but we still want encrypted response
        console.log('[TX] encrypted=1', 'no-body');
      }
    } else {
      console.log(
        '[TX] encrypted=0',
        'ctype=',
        (hdrs['Content-Type'] || (config.headers as any)?.['Content-Type']) ?? 'application/json'
      );
    }


    config.headers = hdrs as any;
    return config;
  }

  private async handleResponse<T>(response: AxiosResponse<T>): Promise<AxiosResponse<T>> {
    // Decrypt ONLY if server marked the response as encrypted and shared secret is set
    const sharedSecret =
      SECURITY_CONFIG.API.ENCRYPTION.SHARED_SECRET || process.env.API_SHARED_SECRET;
    const isEncrypted =
      !!(
        response.headers &&
        ((response.headers['x-encrypted'] as any) === '1' ||
          (response.headers['X-Encrypted'] as any) === '1')
      );
    const ivHeader = (response.headers &&
      ((response.headers['x-iv'] as any) ||
        (response.headers['X-IV'] as any))) as string | undefined;

    // RX header log
    console.log(
      '[RX] header.encrypted=', isEncrypted,
      'hasIV=', !!ivHeader,
      'data.type=', typeof response.data
    );

    if (SECURITY_CONFIG.API.ENCRYPTION.ENABLED && sharedSecret && isEncrypted && typeof response.data === 'string') {
      const beforeSample = String(response.data).slice(0, 60);
      response.data = await this.decryptWithSharedSecret(response.data as any, sharedSecret, ivHeader) as any;
      // RX decrypted log
      console.log(
        '[RX] decrypted',
        'before.sample=', beforeSample,
        'after.type=', typeof response.data
      );
    } else {
      // RX plaintext log
      console.log('[RX] plaintext', 'type=', typeof response.data);
    }

    // Verify response integrity if header present
    if (response.headers['x-response-hash']) {
      const isValid = await this.verifyResponseIntegrity(response as any);
      if (!isValid) {
        throw new Error('Response integrity check failed');
      }
    }

    return response;
  }

  private handleResponseError(error: any): Error {
    // Detailed client error log
    try {
      const resp = error.response;
      const reqCfg = error.config || {};
      const headers = (resp && resp.headers) || {};
      const reqId = headers['x-request-id'] || reqCfg.headers?.['X-Request-ID'];
      const isEncrypted = headers['x-encrypted'] === '1' || headers['X-Encrypted'] === '1';
      const iv = headers['x-iv'] || headers['X-IV'];

      console.error('[CLIENT ERR]', {
        status: resp?.status,
        url: reqCfg?.baseURL ? (reqCfg.baseURL + reqCfg.url) : reqCfg.url,
        method: reqCfg?.method,
        reqId,
        isEncrypted,
        hasIV: !!iv,
        respType: typeof resp?.data,
        respDataSample: typeof resp?.data === 'string' ? String(resp.data).slice(0, 120) : undefined,
        respJsonKeys: resp?.data && typeof resp.data === 'object' ? Object.keys(resp.data) : undefined,
      });
    } catch (e) {
      console.error('[CLIENT ERR] logging failure', e);
    }

    if (error.code === 'CERTIFICATE_VERIFY_FAILED') {
      throw new Error('SSL certificate verification failed');
    }
    if (error.response?.status === 429) {
      throw new Error('Rate limit exceeded');
    }
    return error;
  }

  // Shared-secret AES-256-CBC helpers (IV from Expo RNG)
  private async encryptWithSharedSecret(
    plaintext: string,
    secret: string
  ): Promise<{ payload: string; ivBase64: string }> {
    try {
      const ivBytes = await Crypto.getRandomBytesAsync(16);
      const words: number[] = [];
      for (let i = 0; i < ivBytes.length; i += 4) {
        words.push(
          ((ivBytes[i] || 0) << 24) |
          ((ivBytes[i + 1] || 0) << 16) |
          ((ivBytes[i + 2] || 0) << 8) |
          (ivBytes[i + 3] || 0)
        );
      }
      const ivWordArray = CryptoJS.lib.WordArray.create(words, ivBytes.length);
      const keyWordArray = CryptoJS.SHA256(secret);
      const cipherParams = CryptoJS.AES.encrypt(plaintext, keyWordArray, {
        iv: ivWordArray,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
      const payload = cipherParams.ciphertext.toString(CryptoJS.enc.Base64);
      const ivBase64 = CryptoJS.enc.Base64.stringify(ivWordArray);

      // ENC debug
      console.log('[CLIENT ENC]', {
        plainLen: plaintext.length,
        ivLen: ivBase64.length,
        ctSample: payload.slice(0, 80),
      });

      return { payload, ivBase64 };
    } catch (e: any) {
      console.error('[CLIENT ENC] failed', { msg: e?.message });
      throw e;
    }
  }

  private async decryptWithSharedSecret(
    ciphertextBase64: string,
    secret: string,
    ivBase64?: string
  ): Promise<any> {
    try {
      if (!ivBase64) throw new Error('Missing IV for shared-secret decryption');
      const keyWordArray = CryptoJS.SHA256(secret);
      const ivWordArray = CryptoJS.enc.Base64.parse(ivBase64);
      const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: CryptoJS.enc.Base64.parse(ciphertextBase64) } as any,
        keyWordArray,
        {
          iv: ivWordArray,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        }
      );
      const text = CryptoJS.enc.Utf8.stringify(decrypted);

      // DEC debug
      console.log('[CLIENT DEC]', {
        hasIV: !!ivBase64,
        ctSample: String(ciphertextBase64 || '').slice(0, 80),
        outType: 'string',
        outLen: text?.length ?? 0,
      });

      try {
        return JSON.parse(text);
      } catch {
        return text as any;
      }
    } catch (e: any) {
      console.error('[CLIENT DEC] failed', {
        msg: e?.message,
        hasIV: !!ivBase64,
        ctSample: String(ciphertextBase64 || '').slice(0, 120),
      });
      throw e;
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

    if (this.lastRequestTime.has(key)) {
      const lastTime = this.lastRequestTime.get(key) || 0;
      if (now - lastTime > 60000) {
        this.requestCount.delete(key);
        this.lastRequestTime.delete(key);
      }
    }

    const currentCount = this.requestCount.get(key) || 0;
    if (currentCount >= SECURITY_CONFIG.API.RATE_LIMIT.REQUESTS_PER_MINUTE) {
      throw new Error('Rate limit exceeded');
    }

    this.requestCount.set(key, currentCount + 1);
    this.lastRequestTime.set(key, now);
  }

  private getRateLimitKey(url: string): string {
    const endpoint = url.split('?')[0].split('/').pop() || 'default';
    return endpoint;
  }

  // Encrypt request data with device key (used for local storage, not transport)
  private async encryptRequestData(data: any): Promise<string> {
    const jsonString = JSON.stringify(data);
    return await encryptionService.encrypt(jsonString);
  }

  // Decrypt response data with device key (used if your API actually returns encrypted blobs)
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

  // Secure GET/POST/PUT/DELETE
  public async secureGet<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    try {
      const finalConfig = await this.prepareRequest({ ...(config || {}), url });
      const res = await rnFetch(this.baseURL + url, {
        method: 'GET',
        timeoutInterval: (finalConfig.timeout as any) || this.defaultTimeout,
        headers: finalConfig.headers as any,
        sslPinning: {
          certs: ['api_finguard_prod', 'api_finguard_backup', 'api_finguard_staging']
        },
        trustSelfSigned: false,
      });
      const headers: any = res.headers || {};
      const text = (res as any).bodyString as string;
      const response: AxiosResponse<any> = { data: text, status: res.status, statusText: String(res.status), headers, config: finalConfig as any, request: {} };
      const handled = await this.handleResponse(response);
      return handled.data as T;
    } catch (error: any) {
      throw this.handleApiError(this.handleResponseError(error));
    }
  }

  public async securePost<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const finalConfig = await this.prepareRequest({ ...(config || {}), url, data, method: 'POST' });
      const res = await rnFetch(this.baseURL + url, {
        method: 'POST',
        timeoutInterval: (finalConfig.timeout as any) || this.defaultTimeout,
        headers: finalConfig.headers as any,
        body: finalConfig.data as any,
        sslPinning: { certs: ['api_finguard_prod', 'api_finguard_backup', 'api_finguard_staging'] },
        trustSelfSigned: false,
      });
      const headers: any = res.headers || {};
      const text = (res as any).bodyString as string;
      const response: AxiosResponse<any> = { data: text, status: res.status, statusText: String(res.status), headers, config: finalConfig as any, request: {} };
      const handled = await this.handleResponse(response);
      return handled.data as T;
    } catch (error: any) {
      throw this.handleApiError(this.handleResponseError(error));
    }
  }

  public async securePut<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const finalConfig = await this.prepareRequest({ ...(config || {}), url, data, method: 'PUT' });
      const res = await rnFetch(this.baseURL + url, {
        method: 'PUT',
        timeoutInterval: (finalConfig.timeout as any) || this.defaultTimeout,
        headers: finalConfig.headers as any,
        body: finalConfig.data as any,
        sslPinning: { certs: ['api_finguard_prod', 'api_finguard_backup', 'api_finguard_staging'] },
        trustSelfSigned: false,
      });
      const headers: any = res.headers || {};
      const text = (res as any).bodyString as string;
      const response: AxiosResponse<any> = { data: text, status: res.status, statusText: String(res.status), headers, config: finalConfig as any, request: {} };
      const handled = await this.handleResponse(response);
      return handled.data as T;
    } catch (error: any) {
      throw this.handleApiError(this.handleResponseError(error));
    }
  }

  public async secureDelete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    try {
      const finalConfig = await this.prepareRequest({ ...(config || {}), url, method: 'DELETE' });
      const res = await rnFetch(this.baseURL + url, {
        method: 'DELETE',
        timeoutInterval: (finalConfig.timeout as any) || this.defaultTimeout,
        headers: finalConfig.headers as any,
        sslPinning: { certs: ['api_finguard_prod', 'api_finguard_backup', 'api_finguard_staging'] },
        trustSelfSigned: false,
      });
      const headers: any = res.headers || {};
      const text = (res as any).bodyString as string;
      const response: AxiosResponse<any> = { data: text, status: res.status, statusText: String(res.status), headers, config: finalConfig as any, request: {} };
      const handled = await this.handleResponse(response);
      return handled.data as T;
    } catch (error: any) {
      throw this.handleApiError(this.handleResponseError(error));
    }
  }

  // Handle API errors
  private handleApiError(error: any): Error {
    if (error.response) {
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
      return new Error('Network connection failed');
    } else {
      return new Error(error.message || 'Unknown error occurred');
    }
  }

  public setAuthToken(token: string): void {
    this.authToken = token;
  }

  public clearAuthToken(): void {
    this.authToken = undefined;
  }

  public updateBaseURL(baseURL: string): void {
    this.baseURL = baseURL;
  }

  // getApiClient removed because we no longer expose axios instance
}

// Export singleton instance
export const secureApiService = SecureApiService.getInstance();

// Utility functions
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
