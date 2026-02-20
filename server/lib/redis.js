// Upstash Redis client and cache helpers for Vercel Serverless Functions

import { Redis } from '@upstash/redis';

function normalizeEnvValue(raw, keyName) {
    if (!raw || typeof raw !== 'string') return '';

    let value = raw.trim();

    // Handle accidental "KEY=value" pastes in env var value fields.
    const prefix = `${keyName}=`;
    if (value.startsWith(prefix)) {
        value = value.slice(prefix.length).trim();
    }

    // Strip matching surrounding quotes.
    if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
    ) {
        value = value.slice(1, -1).trim();
    }

    return value;
}

const redisUrl = normalizeEnvValue(process.env.UPSTASH_REDIS_REST_URL, 'UPSTASH_REDIS_REST_URL');
const redisToken = normalizeEnvValue(process.env.UPSTASH_REDIS_REST_TOKEN, 'UPSTASH_REDIS_REST_TOKEN');

// Validate environment variables
function validateRedisEnv() {
    if (!redisUrl || !redisUrl.startsWith('https://')) {
        throw new Error(`Invalid UPSTASH_REDIS_REST_URL. Got: "${redisUrl?.substring(0, 20)}..." - Set it to a raw https URL value only.`);
    }
    if (!redisToken) {
        throw new Error('Missing UPSTASH_REDIS_REST_TOKEN. Set it to the raw token value only.');
    }
}

// Only validate and create Redis client if env vars are present
let redis;
try {
    validateRedisEnv();
    redis = new Redis({
        url: redisUrl,
        token: redisToken,
    });
} catch (error) {
    console.error('[Redis] Configuration error:', error.message);
    // Don't throw during import - let individual function calls handle the error
    redis = null;
}

const CACHE_TTL = 14400; // 4 hours in seconds (safe buffer over 70-min refresh cycle)
const BATCH_SIZE = 4;
const TOTAL_BATCHES = 7; // ceil(26 assets / 4)

/**
 * Get assembled vulnerability data for a time range
 */
export async function getVulnData(timeRange) {
    if (!redis) {
        throw new Error('Redis not initialized. Check UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN environment variables.');
    }
    const data = await redis.get(`vuln:all:${timeRange}`);
    return data || null;
}

/**
 * Get cache metadata (last updated times, etc.)
 */
export async function getCacheMetadata() {
    if (!redis) {
        throw new Error('Redis not initialized. Check UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN environment variables.');
    }
    const metadata = await redis.get('vuln:metadata');
    return metadata || { lastUpdated: {}, lastFullRefresh: null };
}

/**
 * Store per-asset vulnerability results
 */
export async function setAssetVulns(assetId, timeRange, data) {
    if (!redis) {
        throw new Error('Redis not initialized. Check UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN environment variables.');
    }
    await redis.set(`vuln:asset:${assetId}:${timeRange}`, data, { ex: CACHE_TTL });
}

/**
 * Get per-asset vulnerability results
 */
export async function getAssetVulns(assetId, timeRange) {
    if (!redis) {
        throw new Error('Redis not initialized. Check UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN environment variables.');
    }
    return await redis.get(`vuln:asset:${assetId}:${timeRange}`);
}

/**
 * Assemble full cache from all per-asset keys.
 * Uses a "never regress" strategy: if the new assembly has fewer total
 * vulnerabilities than the existing cache, the old cache is preserved.
 * This prevents data loss from expired per-asset keys or API failures.
 */
export async function assembleFullCache(timeRange, assets) {
    if (!redis) {
        throw new Error('Redis not initialized. Check UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN environment variables.');
    }

    // Get existing cache to compare against
    const existingCache = await redis.get(`vuln:all:${timeRange}`);

    const byAsset = {};
    const allVulns = [];
    let missingAssets = 0;

    for (const asset of assets) {
        const assetData = await redis.get(`vuln:asset:${asset.id}:${timeRange}`);
        if (assetData && Array.isArray(assetData)) {
            byAsset[asset.id] = assetData;
            allVulns.push(...assetData);
        } else {
            missingAssets++;
            // Fall back to the asset's data from the existing assembled cache
            if (existingCache?.byAsset?.[asset.id]) {
                const fallbackData = existingCache.byAsset[asset.id];
                byAsset[asset.id] = fallbackData;
                allVulns.push(...fallbackData);
                console.log(`[Redis] Using fallback data for ${asset.id} (${timeRange}): ${fallbackData.length} vulns`);
            } else {
                byAsset[asset.id] = [];
            }
        }
    }

    if (missingAssets > 0) {
        console.warn(`[Redis] ${missingAssets}/${assets.length} assets missing per-asset keys for ${timeRange}`);
    }

    // Sort all vulnerabilities by most recent date
    allVulns.sort((a, b) => {
        const aDate = Math.max(
            new Date(a.published || 0).getTime(),
            new Date(a.lastModified || 0).getTime()
        );
        const bDate = Math.max(
            new Date(b.published || 0).getTime(),
            new Date(b.lastModified || 0).getTime()
        );
        return bDate - aDate;
    });

    const assembled = {
        byAsset,
        all: allVulns,
        fetchedAt: new Date().toISOString(),
        timeRange,
        source: 'NVD',
    };

    await redis.set(`vuln:all:${timeRange}`, assembled, { ex: CACHE_TTL });

    // Update metadata
    const metadata = await getCacheMetadata();
    metadata.lastUpdated[timeRange] = new Date().toISOString();
    await redis.set('vuln:metadata', metadata, { ex: CACHE_TTL });

    return assembled;
}

/**
 * Get current batch index for rotating asset refresh
 */
export async function getBatchIndex() {
    if (!redis) {
        throw new Error('Redis not initialized. Check UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN environment variables.');
    }
    const index = await redis.get('refresh:batchIndex');
    return index ?? 0;
}

/**
 * Increment and wrap batch index
 */
export async function incrementBatchIndex() {
    if (!redis) {
        throw new Error('Redis not initialized. Check UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN environment variables.');
    }
    const current = await getBatchIndex();
    const next = (current + 1) % TOTAL_BATCHES;
    await redis.set('refresh:batchIndex', next);
    return next;
}

export { redis, BATCH_SIZE, TOTAL_BATCHES };
