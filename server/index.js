// Heimdall Backend Server
// Provides cached vulnerability data to avoid rate limiting on NVD API

import express from 'express';
import cors from 'cors';
import cron from 'node-cron';
import path from 'path';
import { fileURLToPath } from 'url';
import { VulnerabilityCache } from './services/vulnCache.js';
import { fetchAllVulnerabilities } from './services/nvdService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize cache
const vulnCache = new VulnerabilityCache();

// Middleware
// CORS configuration - allows requests from your Hostinger domain
const corsOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
    : '*';

app.use(cors({
    origin: corsOrigins,
    methods: ['GET', 'POST'],
    credentials: true
}));
app.use(express.json());

// Serve static files from the built frontend (production)
const distPath = path.join(__dirname, '../dist');
app.use(express.static(distPath));

// ===================
// API Routes
// ===================

// Get cached vulnerability data
app.get('/api/vulnerabilities', async (req, res) => {
    try {
        const timeRange = req.query.timeRange || '7d';
        const data = await vulnCache.getData(timeRange);

        if (!data) {
            return res.status(503).json({
                error: 'Cache not ready',
                message: 'Vulnerability data is still being fetched. Please try again in a few minutes.'
            });
        }

        res.json({
            success: true,
            data,
            cacheInfo: {
                lastUpdated: vulnCache.getLastUpdated(timeRange),
                nextUpdate: vulnCache.getNextUpdate(),
                timeRange
            }
        });
    } catch (error) {
        console.error('Error fetching vulnerabilities:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get cache status
app.get('/api/status', (req, res) => {
    res.json({
        status: 'online',
        cacheStatus: vulnCache.getStatus(),
        uptime: process.uptime(),
        lastUpdated: vulnCache.getLastUpdated('7d'),
        nextUpdate: vulnCache.getNextUpdate()
    });
});

// Manual refresh endpoint (protected - requires API key in production)
app.post('/api/refresh', async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    const expectedKey = process.env.ADMIN_API_KEY;

    if (expectedKey && apiKey !== expectedKey) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        console.log('Manual refresh triggered');
        await refreshCache();
        res.json({ success: true, message: 'Cache refresh initiated' });
    } catch (error) {
        console.error('Manual refresh failed:', error);
        res.status(500).json({ error: 'Refresh failed' });
    }
});

// Serve frontend for all other routes (SPA support)
app.get('*', (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
});

// ===================
// Cache Refresh Logic
// ===================

async function refreshCache() {
    console.log(`[${new Date().toISOString()}] Starting cache refresh...`);

    const timeRanges = ['7d', '30d', '90d'];

    for (const timeRange of timeRanges) {
        try {
            console.log(`Fetching vulnerabilities for ${timeRange}...`);
            const data = await fetchAllVulnerabilities(timeRange);
            await vulnCache.setData(timeRange, data);
            console.log(`Cached ${data.all?.length || 0} vulnerabilities for ${timeRange}`);
        } catch (error) {
            console.error(`Failed to fetch ${timeRange} data:`, error.message);
        }
    }

    console.log(`[${new Date().toISOString()}] Cache refresh complete`);
}

// ===================
// Scheduled Jobs
// ===================

// Refresh cache every hour
cron.schedule('0 * * * *', async () => {
    console.log('Hourly cache refresh triggered');
    await refreshCache();
});

// Also refresh at startup
async function initialize() {
    console.log('Heimdall Backend Server starting...');
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);

    // Load existing cache from disk
    await vulnCache.loadFromDisk();

    // Check if cache needs refresh
    const lastUpdated = vulnCache.getLastUpdated('7d');
    const oneHourAgo = Date.now() - (60 * 60 * 1000);

    if (!lastUpdated || new Date(lastUpdated).getTime() < oneHourAgo) {
        console.log('Cache is stale or empty, refreshing...');
        await refreshCache();
    } else {
        console.log('Cache is fresh, using existing data');
    }
}

// ===================
// Start Server
// ===================

app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    await initialize();
});

export default app;
