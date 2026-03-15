// Vercel Serverless Function — serves kill chain analysis from cache

import { getVulnData } from '../server/lib/redis.js';
import { computeKillChains } from '../server/lib/killChainService.js';
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

        const vulnData = await getVulnData(timeRange);

        if (!vulnData) {
            return res.status(503).json({
                error: 'Cache not ready',
                message: 'Vulnerability data is still being fetched. Please try again in a few minutes.',
                success: false
            });
        }

        const data = computeKillChains(vulnData);

        res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=600');
        res.json({ success: true, data });
    } catch (error) {
        console.error('Error computing kill chains:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
}
