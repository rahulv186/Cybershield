const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5050';

async function request(path, options = {}) {
  // Add cache-busting parameter to ensure fresh data
  const separator = path.includes('?') ? '&' : '?';
  const url = `${API_BASE_URL}${path}${separator}_t=${Date.now()}`;
  
  const response = await fetch(url, {
    headers: { 
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      ...(options.headers || {}) 
    },
    ...options
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || 'Request failed');
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  return response.text();
}

export function normalizeThreat(threat) {
  return threat || {};
}

export function normalizeThreats(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (payload && Array.isArray(payload.data)) {
    return payload.data;
  }

  if (payload && Array.isArray(payload.threats)) {
    return payload.threats;
  }

  return [];
}

export async function getThreats() {
  const response = await request('/api/threats');

  if (Array.isArray(response)) {
    return response;
  }

  if (response && Array.isArray(response.data)) {
    return response.data;
  }

  if (response && Array.isArray(response.threats)) {
    return response.threats;
  }

  return [];
}
