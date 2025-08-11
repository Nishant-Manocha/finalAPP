import { encryptionService } from './encryption';
import { deviceSecurityService, SecurityCheckResult } from './deviceSecurity';
import { secureApiService } from './apiSecurity';
import { appSecurityService } from './appSecurity';
import { SECURITY_CONFIG } from './securityConfig';

export interface SecurityStatus {
  isSecure: boolean;
  deviceSecurity: SecurityCheckResult;
  appSecurity: {
    copyPasteDisabled: boolean;
    screenshotsDisabled: boolean;
    backupDisabled: boolean;
  };
  encryptionEnabled: boolean;
  sslPinningEnabled: boolean;
  violations: string[];
}

export class SecurityManager {
  private static instance: SecurityManager;
  private isInitialized: boolean = false;

  private constructor() {}

  public static getInstance(): SecurityManager {
    if (!SecurityManager.instance) {
      SecurityManager.instance = new SecurityManager();
    }
    return SecurityManager.instance;
  }

  // Initialize all security services
  public async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      console.log('Initializing security manager...');

      // Initialize encryption service
      await encryptionService.initialize();
      console.log('✓ Encryption service initialized');

      // Initialize app security features
      await appSecurityService.initialize();
      console.log('✓ App security features initialized');

      // Perform initial security check
      const securityCheck = await this.performSecurityCheck();
      if (!securityCheck.isSecure) {
        console.warn('Security violations detected:', securityCheck.violations);
        if (!__DEV__) {
          throw new Error('Device security check failed');
        }
      }

      this.isInitialized = true;
      console.log('✓ Security manager initialized successfully');
    } catch (error) {
      console.error('Failed to initialize security manager:', error);
      throw new Error('Security initialization failed');
    }
  }

  // Perform comprehensive security check
  public async performSecurityCheck(): Promise<SecurityStatus> {
    const violations: string[] = [];

    // Check device security
    const deviceSecurity = await deviceSecurityService.performSecurityCheck();
    if (!deviceSecurity.isSecure) {
      violations.push(...deviceSecurity.threats);
    }

    // Check app security
    const copyPasteDisabled = await appSecurityService.isCopyPasteDisabled();
    const screenshotsDisabled = await appSecurityService.isScreenshotsDisabled();
    const backupDisabled = await appSecurityService.isBackupDisabled();

    if (SECURITY_CONFIG.APP_SECURITY.COPY_PASTE_DISABLED && !copyPasteDisabled) {
      violations.push('Copy/paste is not disabled');
    }

    if (SECURITY_CONFIG.APP_SECURITY.SCREENSHOT_DISABLED && !screenshotsDisabled) {
      violations.push('Screenshots are not disabled');
    }

    if (SECURITY_CONFIG.APP_SECURITY.BACKUP_DISABLED && !backupDisabled) {
      violations.push('App backup is not disabled');
    }

    // Check encryption status
    const encryptionEnabled = SECURITY_CONFIG.DATA_PROTECTION.SENSITIVE_DATA_ENCRYPTION;
    const sslPinningEnabled = SECURITY_CONFIG.SSL_PINNING.ENABLED;

    return {
      isSecure: violations.length === 0,
      deviceSecurity,
      appSecurity: {
        copyPasteDisabled,
        screenshotsDisabled,
        backupDisabled,
      },
      encryptionEnabled,
      sslPinningEnabled,
      violations,
    };
  }

  // Encrypt sensitive data
  public async encryptData(data: any): Promise<string> {
    if (!this.isInitialized) {
      throw new Error('Security manager not initialized');
    }
    return await encryptionService.encryptSensitiveData(data);
  }

  // Decrypt sensitive data
  public async decryptData(encryptedData: string): Promise<any> {
    if (!this.isInitialized) {
      throw new Error('Security manager not initialized');
    }
    return await encryptionService.decryptSensitiveData(encryptedData);
  }

  // Secure API request
  public async secureApiRequest<T>(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    data?: any
  ): Promise<T> {
    if (!this.isInitialized) {
      throw new Error('Security manager not initialized');
    }

    switch (method) {
      case 'GET':
        return await secureApiService.secureGet<T>(url);
      case 'POST':
        return await secureApiService.securePost<T>(url, data);
      case 'PUT':
        return await secureApiService.securePut<T>(url, data);
      case 'DELETE':
        return await secureApiService.secureDelete<T>(url);
      default:
        throw new Error(`Unsupported HTTP method: ${method}`);
    }
  }

  // Set authentication token
  public setAuthToken(token: string): void {
    if (!this.isInitialized) {
      throw new Error('Security manager not initialized');
    }
    secureApiService.setAuthToken(token);
  }

  // Clear authentication token
  public clearAuthToken(): void {
    if (!this.isInitialized) {
      throw new Error('Security manager not initialized');
    }
    secureApiService.clearAuthToken();
  }

  // Get device information
  public async getDeviceInfo(): Promise<Record<string, any>> {
    return await deviceSecurityService.getDeviceInfo();
  }

  // Show security warning
  public showSecurityWarning(message: string): void {
    appSecurityService.showSecurityWarning(message);
  }

  // Clear clipboard
  public async clearClipboard(): Promise<void> {
    return await appSecurityService.clearClipboard();
  }

  // Rotate encryption keys
  public async rotateEncryptionKeys(): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('Security manager not initialized');
    }
    return await encryptionService.rotateKeys();
  }

  // Clear all security data (for logout)
  public async clearSecurityData(): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('Security manager not initialized');
    }

    try {
      // Clear encryption keys
      await encryptionService.clearKeys();

      // Clear auth token
      secureApiService.clearAuthToken();

      // Clear clipboard
      await appSecurityService.clearClipboard();

      console.log('Security data cleared successfully');
    } catch (error) {
      console.error('Failed to clear security data:', error);
      throw new Error('Failed to clear security data');
    }
  }

  // Validate security requirements
  public async validateSecurityRequirements(): Promise<{
    isValid: boolean;
    issues: string[];
  }> {
    const issues: string[] = [];

    // Check OWASP Top 10 compliance
    const owaspIssues = await this.checkOWASPCompliance();
    issues.push(...owaspIssues);

    // Check CERT-IN guidelines compliance
    const certinIssues = await this.checkCERTINCompliance();
    issues.push(...certinIssues);

    // Check custom security requirements
    const customIssues = await this.checkCustomSecurityRequirements();
    issues.push(...customIssues);

    return {
      isValid: issues.length === 0,
      issues,
    };
  }

  // Check OWASP Top 10 compliance
  private async checkOWASPCompliance(): Promise<string[]> {
    const issues: string[] = [];

    // A01:2021 – Broken Access Control
    if (!SECURITY_CONFIG.SESSION.MAX_SESSIONS) {
      issues.push('OWASP A01: Session management not properly configured');
    }

    // A02:2021 – Cryptographic Failures
    if (!SECURITY_CONFIG.ENCRYPTION.ALGORITHM.includes('AES-256')) {
      issues.push('OWASP A02: AES-256 encryption not properly configured');
    }
    if (!SECURITY_CONFIG.API?.ENCRYPTION?.ENABLED) {
      issues.push('OWASP A02: API request/response encryption not enabled');
    }

    // A04:2021 – Insecure Design
    if (!SECURITY_CONFIG.DEVICE_SECURITY.ROOT_DETECTION_ENABLED) {
      issues.push('OWASP A04: Root/jailbreak detection not enabled');
    }

    // A05:2021 – Security Misconfiguration
    if (!SECURITY_CONFIG.APP_SECURITY.BACKUP_DISABLED) {
      issues.push('OWASP A05: App backup not disabled');
    }
    if (!SECURITY_CONFIG.API?.RATE_LIMIT?.ENABLED) {
      issues.push('OWASP A05: API rate limiting not enabled');
    }

    return issues;
  }

  // Check CERT-IN guidelines compliance
  private async checkCERTINCompliance(): Promise<string[]> {
    const issues: string[] = [];

    // Check for SSL pinning
    if (!SECURITY_CONFIG.SSL_PINNING.ENABLED) {
      issues.push('CERT-IN: SSL pinning not enabled');
    }

    // Check for code obfuscation
    if (!SECURITY_CONFIG.OBFUSCATION.ENABLED) {
      issues.push('CERT-IN: Code obfuscation not enabled');
    }

    // Check for minimum permissions
    if (SECURITY_CONFIG.PERMISSIONS.REQUIRED.length === 0) {
      issues.push('CERT-IN: Required permissions not defined');
    }

    // Validate app.json permissions (best-effort)
    try {
      // Relative to utils/ -> ../app.json
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const appConfig = require('../app.json');
      const androidPerms: string[] = appConfig?.expo?.android?.permissions || [];
      const required = new Set(SECURITY_CONFIG.PERMISSIONS.REQUIRED);

      // Extra permissions present beyond required+optional
      const allowed = new Set([
        ...SECURITY_CONFIG.PERMISSIONS.REQUIRED,
        ...SECURITY_CONFIG.PERMISSIONS.OPTIONAL,
      ]);
      const extras = androidPerms.filter((p: string) => !allowed.has(p));
      if (extras.length > 0) {
        issues.push(`CERT-IN: App requests non-required permissions: ${extras.join(', ')}`);
      }
    } catch (e) {
      issues.push('CERT-IN: Could not automatically verify Android permissions (app.json not accessible at runtime)');
    }

    return issues;
  }

  // Check custom security requirements
  private async checkCustomSecurityRequirements(): Promise<string[]> {
    const issues: string[] = [];

    // Check for SHA-256 signing
    // This would require checking the actual app signature

    // Check for code minification
    if (!SECURITY_CONFIG.OBFUSCATION.MINIFY_ENABLED) {
      issues.push('Custom: Code minification not enabled');
    }

    // Check for source map disabling
    if (!SECURITY_CONFIG.OBFUSCATION.SOURCE_MAP_DISABLED) {
      issues.push('Custom: Source maps not disabled');
    }

    return issues;
  }

  // Get security configuration
  public getSecurityConfig(): typeof SECURITY_CONFIG {
    return SECURITY_CONFIG;
  }

  // Check if security manager is initialized
  public isSecurityInitialized(): boolean {
    return this.isInitialized;
  }
}

// Export singleton instance
export const securityManager = SecurityManager.getInstance();

// Utility functions
export const initializeSecurity = async (): Promise<void> => {
  return await securityManager.initialize();
};

export const performSecurityCheck = async (): Promise<SecurityStatus> => {
  return await securityManager.performSecurityCheck();
};

export const encryptData = async (data: any): Promise<string> => {
  return await securityManager.encryptData(data);
};

export const decryptData = async (encryptedData: string): Promise<any> => {
  return await securityManager.decryptData(encryptedData);
};

export const secureApiRequest = async <T>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  data?: any
): Promise<T> => {
  return await securityManager.secureApiRequest<T>(method, url, data);
};

export const setAuthToken = (token: string): void => {
  securityManager.setAuthToken(token);
};

export const clearAuthToken = (): void => {
  securityManager.clearAuthToken();
};

export const getDeviceInfo = async (): Promise<Record<string, any>> => {
  return await securityManager.getDeviceInfo();
};

export const showSecurityWarning = (message: string): void => {
  securityManager.showSecurityWarning(message);
};

export const clearClipboard = async (): Promise<void> => {
  return await securityManager.clearClipboard();
};

export const rotateEncryptionKeys = async (): Promise<void> => {
  return await securityManager.rotateEncryptionKeys();
};

export const clearSecurityData = async (): Promise<void> => {
  return await securityManager.clearSecurityData();
};

export const validateSecurityRequirements = async (): Promise<{
  isValid: boolean;
  issues: string[];
}> => {
  return await securityManager.validateSecurityRequirements();
};
