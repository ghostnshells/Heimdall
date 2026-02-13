// Frontend lifecycle service — communicates with lifecycle API endpoints
// All write operations require authentication (uses fetchWithAuth)

import { fetchWithAuth } from './authService';

const LIFECYCLE_API = '/api/lifecycle';

// Valid statuses (must match backend)
export const STATUSES = [
    { value: 'new', label: 'New', color: '#71717a' },
    { value: 'acknowledged', label: 'Acknowledged', color: '#3b82f6' },
    { value: 'in_progress', label: 'In Progress', color: '#f59e0b' },
    { value: 'patched', label: 'Patched', color: '#22c55e' },
    { value: 'mitigated', label: 'Mitigated', color: '#06b6d4' },
    { value: 'accepted_risk', label: 'Accepted Risk', color: '#a855f7' },
    { value: 'false_positive', label: 'False Positive', color: '#6b7280' }
];

export function getStatusInfo(status) {
    return STATUSES.find(s => s.value === status) || STATUSES[0];
}

/**
 * Get status for a specific CVE
 */
export async function getVulnStatus(cveId) {
    const response = await fetchWithAuth(`${LIFECYCLE_API}/status?cveId=${encodeURIComponent(cveId)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to get status');
    return data.data;
}

/**
 * Update status for a specific CVE
 */
export async function setVulnStatus(cveId, status, notes = '') {
    const response = await fetchWithAuth(`${LIFECYCLE_API}/status?cveId=${encodeURIComponent(cveId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, notes })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to update status');
    return data.data;
}

/**
 * Get audit trail for a CVE
 */
export async function getAuditTrail(cveId) {
    const response = await fetchWithAuth(`${LIFECYCLE_API}/audit?cveId=${encodeURIComponent(cveId)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to get audit trail');
    return data.data;
}

/**
 * Get SLA configuration
 */
export async function getSLAConfig() {
    const response = await fetchWithAuth(`${LIFECYCLE_API}/sla`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to get SLA config');
    return data.data;
}

/**
 * Update SLA configuration
 */
export async function setSLAConfig(config) {
    const response = await fetchWithAuth(`${LIFECYCLE_API}/sla`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to update SLA config');
    return data.data;
}

/**
 * Bulk update status for multiple CVEs
 */
export async function bulkUpdateStatus(cveIds, status, notes = '') {
    const response = await fetchWithAuth(`${LIFECYCLE_API}/bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cveIds, status, notes })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to bulk update');
    return data.data;
}

/**
 * Calculate SLA deadline (client-side, for display only)
 */
export function calculateSLADeadline(publishedDate, severity, slaConfig) {
    const defaults = { critical: 7, high: 30, medium: 90, low: 180 };
    const config = slaConfig || defaults;
    const severityKey = severity?.toLowerCase() || 'medium';
    const days = config[severityKey] || config.medium;

    const deadline = new Date(publishedDate);
    deadline.setDate(deadline.getDate() + days);
    return deadline;
}

/**
 * Get SLA days remaining (client-side)
 */
export function getSLADaysRemaining(publishedDate, severity, slaConfig) {
    const deadline = calculateSLADeadline(publishedDate, severity, slaConfig);
    return Math.ceil((deadline - new Date()) / (1000 * 60 * 60 * 24));
}

/**
 * Check if SLA is breached (client-side)
 */
export function isSLABreached(publishedDate, severity, status, slaConfig) {
    const terminalStatuses = ['patched', 'mitigated', 'accepted_risk', 'false_positive'];
    if (terminalStatuses.includes(status)) return false;
    return getSLADaysRemaining(publishedDate, severity, slaConfig) < 0;
}
