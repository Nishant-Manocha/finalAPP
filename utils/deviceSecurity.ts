import { Platform, NativeModules } from 'react-native';
import * as Device from 'expo-device';
import * as Application from 'expo-application';
import { ROOT_DETECTION_PATTERNS, JAILBREAK_DETECTION_PATTERNS, EMULATOR_DETECTION_PATTERNS, DEVELOPMENT_MODE_INDICATORS, SECURITY_CONFIG } from './securityConfig';

export interface SecurityCheckResult {
  isSecure: boolean;
  threats: string[];
  details: Record<string, any>;
}

export class DeviceSecurityService {
  private static instance: DeviceSecurityService;

  private constructor() {
    console.log('[DeviceSecurityService] Constructor called');
  }

  public static getInstance(): DeviceSecurityService {
    if (!DeviceSecurityService.instance) {
      console.log('[DeviceSecurityService] Creating new instance');
      DeviceSecurityService.instance = new DeviceSecurityService();
    }
    return DeviceSecurityService.instance;
  }

  public async performSecurityCheck(): Promise<SecurityCheckResult> {
    console.log('[DeviceSecurityService] Performing comprehensive security check');
    const threats: string[] = [];
    const details: Record<string, any> = {};

    try {
      if (SECURITY_CONFIG.DEVICE_SECURITY.ROOT_DETECTION_ENABLED || SECURITY_CONFIG.DEVICE_SECURITY.JAILBREAK_DETECTION_ENABLED) {
        const rootCheck = await this.checkForRootJailbreak();
        if (!rootCheck.isSecure) {
          threats.push('Root/Jailbreak detected');
          details.rootCheck = rootCheck;
        }
      }
    } catch (error) {
      console.error('[DeviceSecurityService] Error during root/jailbreak check:', error);
    }

    try {
      if (SECURITY_CONFIG.DEVICE_SECURITY.EMULATOR_DETECTION_ENABLED) {
        const emulatorCheck = await this.checkForEmulator();
        if (!emulatorCheck.isSecure) {
          threats.push('Emulator detected');
          details.emulatorCheck = emulatorCheck;
        }
      }
    } catch (error) {
      console.error('[DeviceSecurityService] Error during emulator check:', error);
    }

    try {
      if (SECURITY_CONFIG.DEVICE_SECURITY.DEVELOPMENT_MODE_DETECTION_ENABLED) {
        const devModeCheck = await this.checkDevelopmentMode();
        if (!devModeCheck.isSecure) {
          threats.push('Development mode detected');
          details.devModeCheck = devModeCheck;
        }
      }
    } catch (error) {
      console.error('[DeviceSecurityService] Error during development mode check:', error);
    }

    try {
      if (SECURITY_CONFIG.DEVICE_SECURITY.DEBUG_MODE_DETECTION_ENABLED) {
        const debugCheck = await this.checkDebugMode();
        if (!debugCheck.isSecure) {
          threats.push('Debug mode detected');
          details.debugCheck = debugCheck;
        }
      }
    } catch (error) {
      console.error('[DeviceSecurityService] Error during debug mode check:', error);
    }

    console.log('[DeviceSecurityService] Security check completed', { threats, details });

    return {
      isSecure: threats.length === 0,
      threats,
      details,
    };
  }

  private async checkForRootJailbreak(): Promise<SecurityCheckResult> {
    console.log('[DeviceSecurityService] Checking for root/jailbreak');
    const threats: string[] = [];
    const details: Record<string, any> = {};

    if (Platform.OS === 'android') {
      const rootPaths = ROOT_DETECTION_PATTERNS.ANDROID || [];
      for (const path of rootPaths) {
        try {
          console.log('[DeviceSecurityService] Checking root path:', path);
          if (await this.checkFileExists(path)) {
            threats.push(`Root file found: ${path}`);
            details.rootFiles = details.rootFiles || [];
            details.rootFiles.push(path);
          }
        } catch (error) {
          console.warn('[DeviceSecurityService] Error checking root file existence:', error);
        }
      }

      const buildProps = await this.getBuildProperties();
      console.log('[DeviceSecurityService] Android build properties:', buildProps);

      if (buildProps.ro_debuggable === '1') {
        threats.push('Device is debuggable');
        details.debuggable = true;
      }
      if (buildProps.ro_secure === '0') {
        threats.push('Device is not secure');
        details.secure = false;
      }
    } else if (Platform.OS === 'ios') {
      const jailbreakPaths = ROOT_DETECTION_PATTERNS.IOS || [];
      for (const path of jailbreakPaths) {
        try {
          console.log('[DeviceSecurityService] Checking jailbreak path:', path);
          if (await this.checkFileExists(path)) {
            threats.push(`Jailbreak file found: ${path}`);
            details.jailbreakFiles = details.jailbreakFiles || [];
            details.jailbreakFiles.push(path);
          }
        } catch (error) {
          console.warn('[DeviceSecurityService] Error checking jailbreak file existence:', error);
        }
      }

      if (await this.checkFileExists('/Applications/Cydia.app')) {
        threats.push('Cydia detected');
        details.cydia = true;
      }
    }

    return {
      isSecure: threats.length === 0,
      threats,
      details,
    };
  }

  private async checkForEmulator(): Promise<SecurityCheckResult> {
    console.log('[DeviceSecurityService] Checking for emulator');
    const threats: string[] = [];
    const details: Record<string, any> = {};

    if (Platform.OS === 'android') {
      const buildProps = await this.getBuildProperties();
      console.log('[DeviceSecurityService] Android build properties for emulator check:', buildProps);

      if (buildProps.ro_kernel_qemu === '1') {
        threats.push('QEMU emulator detected');
        details.qemu = true;
      }

      if (buildProps.ro_hardware === 'goldfish' || buildProps.ro_hardware === 'ranchu') {
        threats.push('Android emulator detected');
        details.emulator = buildProps.ro_hardware;
      }

      const emulatorProps = EMULATOR_DETECTION_PATTERNS.ANDROID || [];
      for (const prop of emulatorProps) {
        if (
          buildProps[prop] &&
          typeof buildProps[prop] === 'string' && // safe check before includes
          (buildProps[prop].includes('sdk') || buildProps[prop].includes('emulator'))
        ) {
          threats.push(`Emulator property detected: ${prop}`);
          details.emulatorProps = details.emulatorProps || [];
          details.emulatorProps.push(prop);
        }
      }
    } else if (Platform.OS === 'ios') {
      const simulatorProps = EMULATOR_DETECTION_PATTERNS.IOS || [];
      for (const prop of simulatorProps) {
        if (process.env[prop]) {
          threats.push(`iOS simulator detected: ${prop}`);
          details.simulatorProps = details.simulatorProps || [];
          details.simulatorProps.push(prop);
        }
      }
    }

    return {
      isSecure: threats.length === 0,
      threats,
      details,
    };
  }

  private async checkDevelopmentMode(): Promise<SecurityCheckResult> {
    console.log('[DeviceSecurityService] Checking for development mode');
    const threats: string[] = [];
    const details: Record<string, any> = {};

    if (SECURITY_CONFIG.DEVICE_SECURITY.DEVELOPMENT_MODE_DETECTION_ENABLED && typeof __DEV__ !== 'undefined' && __DEV__) {
      threats.push('Application running in development mode');
      details.developmentMode = true;
    }

    if (Platform.OS === 'ios') {
      const devIndicators = DEVELOPMENT_MODE_INDICATORS.IOS || [];
      for (const indicator of devIndicators) {
        if ((process.env as any)[indicator]) {
          threats.push(`Development indicator found: ${indicator}`);
          details.devIndicators = details.devIndicators || [];
          details.devIndicators.push(indicator);
        }
      }
    }

    if (Platform.OS === 'android') {
      const buildProps = await this.getBuildProperties();
      console.log('[DeviceSecurityService] Android build properties for development check:', buildProps);
      const devIndicators = DEVELOPMENT_MODE_INDICATORS.ANDROID || [];

      for (const indicator of devIndicators) {
        const [key, value] = indicator.split('=');
        if ((buildProps as any)[key] === value) {
          threats.push(`Development build property: ${indicator}`);
          details.devBuildProps = details.devBuildProps || [];
          details.devBuildProps.push(indicator);
        }
      }
    }

    return {
      isSecure: threats.length === 0,
      threats,
      details,
    };
  }

  private async checkDebugMode(): Promise<SecurityCheckResult> {
    console.log('[DeviceSecurityService] Checking for debug mode');
    const threats: string[] = [];
    const details: Record<string, any> = {};

    if (Platform.OS === 'android') {
      const buildProps = await this.getBuildProperties();
      console.log('[DeviceSecurityService] Android build properties for debug check:', buildProps);
      if (SECURITY_CONFIG.DEVICE_SECURITY.DEBUG_MODE_DETECTION_ENABLED && (buildProps as any).ro_debuggable === '1') {
        threats.push('Application is debuggable');
        details.debuggable = true;
      }
    }

    try {
      if (SECURITY_CONFIG.DEVICE_SECURITY.DEBUG_MODE_DETECTION_ENABLED && typeof (global as any).__REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined') {
        threats.push('React DevTools detected');
        details.reactDevTools = true;
      }
    } catch (error) {
      console.warn('[DeviceSecurityService] React DevTools check failed:', error);
    }

    return {
      isSecure: threats.length === 0,
      threats,
      details,
    };
  }
  

  private async checkFileExists(path: string): Promise<boolean> {
    console.log('[DeviceSecurityService] Checking if file exists:', path);
    try {
      // Placeholder: native implementation needed
      return false;
    } catch (error) {
      console.warn('[DeviceSecurityService] Error in checkFileExists:', error);
      return false;
    }
  }

  private async getBuildProperties(): Promise<Record<string, string>> {
    console.log('[DeviceSecurityService] Getting build properties');
    try {
      // Placeholder: native implementation needed
      return {};
    } catch (error) {
      console.warn('[DeviceSecurityService] Error getting build properties:', error);
      return {};
    }
  }

  public async getDeviceInfo(): Promise<Record<string, any>> {
    console.log('[DeviceSecurityService] Getting device info');
    return {
      platform: Platform.OS,
      version: Platform.Version,
      isDevice: Device.isDevice,
      brand: Device.brand,
      manufacturer: Device.manufacturer,
      modelName: Device.modelName,
      deviceYearClass: Device.deviceYearClass,
      totalMemory: Device.totalMemory,
      supportedCpuArchitectures: Device.supportedCpuArchitectures,
      osName: Device.osName,
      osVersion: Device.osVersion,
      osBuildId: Device.osBuildId,
      osInternalBuildId: Device.osInternalBuildId,
      deviceName: Device.deviceName,
      appVersion: Application.nativeApplicationVersion,
      buildVersion: Application.nativeBuildVersion,
    };
  }
}

export const deviceSecurityService = DeviceSecurityService.getInstance();

export const checkDeviceSecurity = async (): Promise<SecurityCheckResult> => {
  console.log('[DeviceSecurityService] Running checkDeviceSecurity utility function');
  return await deviceSecurityService.performSecurityCheck();
};

export const getDeviceInfo = async (): Promise<Record<string, any>> => {
  console.log('[DeviceSecurityService] Running getDeviceInfo utility function');
  return await deviceSecurityService.getDeviceInfo();
};
