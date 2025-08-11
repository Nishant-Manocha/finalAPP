import { getToken } from "../utils/SecureStore";
import { secureApiService } from "../utils/apiSecurity";
import { SECURITY_CONFIG } from "../utils/securityConfig";

// Resolve and set base URL
const resolvedBaseURL = process.env.SERVER_URL || SECURITY_CONFIG.API.BASE_URL;
secureApiService.updateBaseURL(resolvedBaseURL);

// Initialize auth token from secure storage (best-effort)
(async () => {
  try {
    const token = await getToken();
    if (token) secureApiService.setAuthToken(token);
  } catch {}
})();

const API = {
  get: (url: string, config?: any) => secureApiService.secureGet(url, config),
  post: (url: string, data?: any, config?: any) => secureApiService.securePost(url, data, config),
  put: (url: string, data?: any, config?: any) => secureApiService.securePut(url, data, config),
  delete: (url: string, config?: any) => secureApiService.secureDelete(url, config),
};

export default API;
