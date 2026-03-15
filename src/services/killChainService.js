// Kill Chain Frontend Service
// Fetches /api/kill-chains with memory + localStorage caching (5-min TTL)

const CACHE_KEY_PREFIX = 'panoptes_killchain_v1';
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

const API_URL = import.meta.env.VITE_API_URL
    ? `${import.meta.env.VITE_API_URL}/api/kill-chains`
    : '/api/kill-chains';

// In-memory cache (keyed by timeRange)
const memoryCache = {};

function getCached(timeRange) {
    const fullKey = `${CACHE_KEY_PREFIX}_${timeRange}`;

    const mem = memoryCache[fullKey];
    if (mem && Date.now() - mem.timestamp < CACHE_DURATION) {
        return mem.data;
    }

    try {
        const stored = localStorage.getItem(fullKey);
        if (stored) {
            const { timestamp, data } = JSON.parse(stored);
            if (Date.now() - timestamp < CACHE_DURATION) {
                memoryCache[fullKey] = { timestamp, data };
                return data;
            }
            localStorage.removeItem(fullKey);
        }
    } catch {
        // Ignore localStorage errors
    }

    return null;
}

function setCache(timeRange, data) {
    const fullKey = `${CACHE_KEY_PREFIX}_${timeRange}`;
    const timestamp = Date.now();
    memoryCache[fullKey] = { timestamp, data };

    try {
        localStorage.setItem(fullKey, JSON.stringify({ timestamp, data }));
    } catch {
        // localStorage quota exceeded — memory cache still works
    }
}

/**
 * Fetch kill chain analysis data
 * @param {string} timeRange - Time range (e.g. '7d', '30d')
 * @param {boolean} forceRefresh - Bypass cache
 * @returns {Promise<Object>} Kill chain data
 */
export async function fetchKillChains(timeRange = '7d', forceRefresh = false) {
    if (!forceRefresh) {
        const cached = getCached(timeRange);
        if (cached) return cached;
    }

    const url = `${API_URL}?timeRange=${encodeURIComponent(timeRange)}`;
    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(`Kill chain API error: ${response.status}`);
    }

    const result = await response.json();

    if (!result.success) {
        throw new Error(result.message || 'Failed to fetch kill chain data');
    }

    setCache(timeRange, result.data);
    return result.data;
}

/**
 * Clear kill chain cache (all time range variants)
 */
export function clearKillChainCache() {
    for (const key of Object.keys(memoryCache)) {
        delete memoryCache[key];
    }
    try {
        for (let i = localStorage.length - 1; i >= 0; i--) {
            const key = localStorage.key(i);
            if (key && key.startsWith(CACHE_KEY_PREFIX)) {
                localStorage.removeItem(key);
            }
        }
    } catch {
        // Ignore
    }
}
