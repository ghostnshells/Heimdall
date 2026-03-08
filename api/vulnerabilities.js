// Vercel Serverless Function — serves cached vulnerability data from Upstash Redis

import { getVulnData, getCacheMetadata } from '../server/lib/redis.js';
import { validateTimeRange } from '../server/lib/validation.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const timeRange = req.query.timeRange || '7d';
        if (!validateTimeRange(timeRange)) {
            return res.status(400).json({ error: 'Invalid timeRange. Must be one of: 24h, 7d, 30d, 90d, 119d' });
        }
        const data = await getVulnData(timeRange);

        if (!data) {
            return res.status(503).json({
                error: 'Cache not ready',
                message: 'Vulnerability data is still being fetched. Please try again in a few minutes.',
                success: false
            });
        }

        const metadata = await getCacheMetadata();

        res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=600');
        res.json({
            success: true,
            data,
            cacheInfo: {
                lastUpdated: metadata.lastUpdated[timeRange] || null,
                nextUpdate: null,
                timeRange
            }
        });
    } catch (error) {
        console.error('Error fetching vulnerabilities:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
            message: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
}
