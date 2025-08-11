import { secureApiService } from "../../utils/apiSecurity";

export const apiConnector = async (method, url, bodyData, headers, params) => {
  const config = { headers, params };
  switch ((method || 'GET').toUpperCase()) {
    case 'GET':
      return await secureApiService.secureGet(url, config);
    case 'POST':
      return await secureApiService.securePost(url, bodyData, config);
    case 'PUT':
      return await secureApiService.securePut(url, bodyData, config);
    case 'DELETE':
      return await secureApiService.secureDelete(url, config);
    default:
      return await secureApiService.secureGet(url, config);
  }
};
