// Vulnerability Cache Service
// Stores fetched vulnerability data and persists to disk

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CACHE_DIR = path.join(__dirname, '../cache');
const CACHE_FILE = path.join(CACHE_DIR, 'vulnerabilities.json');

export class VulnerabilityCache {
    constructor() {
        // In-memory cache for fast access
        this.cache = new Map();
        this.metadata = {
            lastUpdated: {},
            refreshInterval: 60 * 60 * 1000, // 1 hour in ms
            nextUpdate: null
        };
    }

    /**
     * Get cached data for a time range
     */
    async getData(timeRange) {
        return this.cache.get(timeRange) || null;
    }

    /**
     * Set cached data for a time range
     */
    async setData(timeRange, data) {
        const enrichedData = {
            ...data,
            cachedAt: new Date().toISOString()
        };

        this.cache.set(timeRange, enrichedData);
        this.metadata.lastUpdated[timeRange] = new Date().toISOString();
        this.metadata.nextUpdate = new Date(Date.now() + this.metadata.refreshInterval).toISOString();

        // Persist to disk
        await this.saveToDisk();
    }

    /**
     * Get last updated timestamp for a time range
     */
    getLastUpdated(timeRange) {
        return this.metadata.lastUpdated[timeRange] || null;
    }

    /**
     * Get next scheduled update time
     */
    getNextUpdate() {
        return this.metadata.nextUpdate;
    }

    /**
     * Get cache status for all time ranges
     */
    getStatus() {
        const status = {};
        for (const [range, data] of this.cache.entries()) {
            status[range] = {
                hasData: true,
                totalVulnerabilities: data.all?.length || 0,
                lastUpdated: this.metadata.lastUpdated[range],
                assetsWithVulns: Object.keys(data.byAsset || {}).filter(
                    k => data.byAsset[k]?.length > 0
                ).length
            };
        }
        return status;
    }

    /**
     * Save cache to disk for persistence across restarts
     */
    async saveToDisk() {
        try {
            // Ensure cache directory exists
            await fs.mkdir(CACHE_DIR, { recursive: true });

            const cacheData = {
                metadata: this.metadata,
                data: Object.fromEntries(this.cache)
            };

            await fs.writeFile(CACHE_FILE, JSON.stringify(cacheData, null, 2));
            console.log('Cache saved to disk');
        } catch (error) {
            console.error('Failed to save cache to disk:', error.message);
        }
    }

    /**
     * Load cache from disk on startup
     */
    async loadFromDisk() {
        try {
            const fileContent = await fs.readFile(CACHE_FILE, 'utf-8');
            const cacheData = JSON.parse(fileContent);

            this.metadata = cacheData.metadata || this.metadata;

            // Restore cache Map from saved data
            if (cacheData.data) {
                for (const [range, data] of Object.entries(cacheData.data)) {
                    this.cache.set(range, data);
                }
            }

            console.log('Cache loaded from disk');
            console.log('Cached time ranges:', Array.from(this.cache.keys()));
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log('No existing cache file, starting fresh');
            } else {
                console.error('Failed to load cache from disk:', error.message);
            }
        }
    }

    /**
     * Clear all cached data
     */
    async clear() {
        this.cache.clear();
        this.metadata.lastUpdated = {};
        this.metadata.nextUpdate = null;

        try {
            await fs.unlink(CACHE_FILE);
        } catch (error) {
            // Ignore if file doesn't exist
        }
    }
}

export default VulnerabilityCache;
