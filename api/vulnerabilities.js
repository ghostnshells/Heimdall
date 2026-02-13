// Vercel Serverless Function — serves cached vulnerability data from Upstash Redis

import { getVulnData, getCacheMetadata } from './lib/redis.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const timeRange = req.query.timeRange || '7d';
        const data = await getVulnData(timeRange);

        if (!data) {
            return res.status(503).json({
                error: 'Cache not ready',
                message: 'Vulnerability data is still being fetched. Please try again in a few minutes.'
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
        res.status(500).json({ error: 'Internal server error' });
    }
}
