import axios from 'axios';
import type { AuditResponse } from '@/types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8765';
const API_TIMEOUT_MS = Number(process.env.NEXT_PUBLIC_API_TIMEOUT_MS ?? '30000');
const AUDIT_TIMEOUT_MS = Number(process.env.NEXT_PUBLIC_AUDIT_TIMEOUT_MS ?? '0');

export const api = axios.create({
  baseURL: API_URL,
  timeout: Number.isFinite(API_TIMEOUT_MS) && API_TIMEOUT_MS > 0 ? API_TIMEOUT_MS : 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const auditURL = async (url: string, jobId?: string): Promise<AuditResponse> => {
  const formData = new FormData();
  formData.append('url', url);
  if (jobId) {
    formData.append('job_id', jobId);
  }

  const response = await api.post('/api/audit', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    // Audits can run longer than two minutes depending on enabled checks/APIs.
    timeout: Number.isFinite(AUDIT_TIMEOUT_MS) && AUDIT_TIMEOUT_MS >= 0 ? AUDIT_TIMEOUT_MS : 0,
  });

  return response.data;
};

export const createWebSocket = (jobId: string): WebSocket => {
  const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8765';
  return new WebSocket(`${WS_URL}/ws/progress/${jobId}`);
};
