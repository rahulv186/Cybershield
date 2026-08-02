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

export async function addBlockedIP(entry) {
  return request('/api/blocked', {
    method: 'POST',
    body: JSON.stringify(entry)
  });
}

export async function getBlockedIPs() {
  const res = await request('/api/blocked');
  // API wraps response as { success, message, data: [...] }
  return Array.isArray(res?.data) ? res.data : (Array.isArray(res) ? res : []);
}

export async function removeBlockedIP(ip) {
  return request(`/api/blocked/${encodeURIComponent(ip)}`, {
    method: 'DELETE'
  });
}

export async function clearBlockedIPs() {
  return request('/api/blocked', {
    method: 'DELETE'
  });
}
