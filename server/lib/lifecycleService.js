// Vulnerability Lifecycle Service — Redis-backed status tracking, audit trail, and SLA management

import { redis } from './redis.js';

// Valid vulnerability lifecycle statuses
export const STATUSES = ['new', 'acknowledged', 'in_progress', 'patched', 'mitigated', 'accepted_risk', 'false_positive'];

// Default SLA configuration (days until breach per severity)
const DEFAULT_SLA = { critical: 7, high: 30, medium: 90, low: 180 };

/**
 * Get vulnerability status for a user
 */
export async function getVulnStatus(userId, cveId) {
    const data = await redis.get(`vuln:status:${userId}:${cveId}`);
    return data || { status: 'new', updatedAt: null, notes: '' };
}

/**
 * Set vulnerability status with audit trail
 */
export async function setVulnStatus(userId, cveId, status, notes = '') {
    if (!STATUSES.includes(status)) {
        throw new Error(`Invalid status: ${status}. Must be one of: ${STATUSES.join(', ')}`);
    }

    const now = new Date().toISOString();
    const previous = await getVulnStatus(userId, cveId);

    // Update current status
    const statusData = { status, updatedAt: now, notes };
    await redis.set(`vuln:status:${userId}:${cveId}`, statusData);

    // Add audit trail entry
    const auditEntry = JSON.stringify({
        from: previous.status,
        to: status,
        notes,
        timestamp: now
    });
    await redis.zadd(`vuln:audit:${userId}:${cveId}`, {
        score: Date.now(),
        member: auditEntry
    });

    return statusData;
}

/**
 * Get audit trail for a vulnerability
 */
export async function getAuditTrail(userId, cveId) {
    const entries = await redis.zrange(`vuln:audit:${userId}:${cveId}`, 0, -1);
    return (entries || []).map(entry => {
        try {
            return JSON.parse(entry);
        } catch {
            return null;
        }
    }).filter(Boolean);
}

/**
 * Get SLA configuration for a user
 */
export async function getSLAConfig(userId) {
    const config = await redis.get(`sla:config:${userId}`);
    return config || DEFAULT_SLA;
}

/**
 * Set SLA configuration for a user
 */
export async function setSLAConfig(userId, config) {
    const sla = {
        critical: config.critical ?? DEFAULT_SLA.critical,
        high: config.high ?? DEFAULT_SLA.high,
        medium: config.medium ?? DEFAULT_SLA.medium,
        low: config.low ?? DEFAULT_SLA.low
    };
    await redis.set(`sla:config:${userId}`, sla);
    return sla;
}

/**
 * Calculate SLA deadline based on severity and configuration
 */
export function calculateSLADeadline(publishedDate, severity, slaConfig) {
    const config = slaConfig || DEFAULT_SLA;
    const severityKey = severity?.toLowerCase() || 'medium';
    const days = config[severityKey] || config.medium;

    const deadline = new Date(publishedDate);
    deadline.setDate(deadline.getDate() + days);
    return deadline.toISOString();
}

/**
 * Check if SLA is breached
 */
export function isSLABreached(publishedDate, severity, status, slaConfig) {
    // Terminal statuses are never breached
    const terminalStatuses = ['patched', 'mitigated', 'accepted_risk', 'false_positive'];
    if (terminalStatuses.includes(status)) return false;

    const deadline = new Date(calculateSLADeadline(publishedDate, severity, slaConfig));
    return new Date() > deadline;
}

/**
 * Get days remaining until SLA breach
 */
export function getSLADaysRemaining(publishedDate, severity, slaConfig) {
    const deadline = new Date(calculateSLADeadline(publishedDate, severity, slaConfig));
    const now = new Date();
    return Math.ceil((deadline - now) / (1000 * 60 * 60 * 24));
}

/**
 * Bulk get statuses for multiple CVEs
 */
export async function getBulkStatuses(userId, cveIds) {
    const results = {};
    // Use pipeline for efficiency
    for (const cveId of cveIds) {
        const data = await redis.get(`vuln:status:${userId}:${cveId}`);
        results[cveId] = data || { status: 'new', updatedAt: null, notes: '' };
    }
    return results;
}

/**
 * Bulk set status for multiple CVEs
 */
export async function setBulkStatus(userId, cveIds, status, notes = '') {
    if (!STATUSES.includes(status)) {
        throw new Error(`Invalid status: ${status}`);
    }

    const results = [];
    for (const cveId of cveIds) {
        const result = await setVulnStatus(userId, cveId, status, notes);
        results.push({ cveId, ...result });
    }
    return results;
}
