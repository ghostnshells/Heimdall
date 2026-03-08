// Shared input validators used by both Express server and Vercel serverless functions

const CVE_ID_REGEX = /^CVE-\d{4}-\d{4,}$/;
const VALID_TIME_RANGES = ['24h', '7d', '30d', '90d', '119d'];

/**
 * Validate password strength.
 * Returns { valid, error } where error describes the first failing rule.
 */
export function validatePasswordStrength(password) {
    if (!password || typeof password !== 'string') {
        return { valid: false, error: 'Password is required' };
    }
    if (password.length < 12) {
        return { valid: false, error: 'Password must be at least 12 characters' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one uppercase letter' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one lowercase letter' };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one number' };
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one special character' };
    }
    return { valid: true, error: null };
}

/**
 * Validate a CVE ID format (e.g. CVE-2024-12345).
 */
export function validateCveId(cveId) {
    return typeof cveId === 'string' && CVE_ID_REGEX.test(cveId);
}

/**
 * Validate a timeRange parameter against the allowed whitelist.
 */
export function validateTimeRange(timeRange) {
    return VALID_TIME_RANGES.includes(timeRange);
}

/**
 * Validate a URL — only http: and https: protocols are allowed.
 */
export function validateUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
        return false;
    }
}
