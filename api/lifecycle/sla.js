// GET/PUT /api/lifecycle/sla — Get or set SLA configuration

import { requireAuth } from '../../server/lib/authMiddleware.js';
import { getSLAConfig, setSLAConfig } from '../../server/lib/lifecycleService.js';

export default requireAuth(async function handler(req, res) {
    const userId = req.user.email;

    if (req.method === 'GET') {
        try {
            const config = await getSLAConfig(userId);
            return res.json({ success: true, data: config });
        } catch (error) {
            console.error('Get SLA error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    if (req.method === 'PUT') {
        try {
            const config = req.body || {};
            const result = await setSLAConfig(userId, config);
            return res.json({ success: true, data: result });
        } catch (error) {
            console.error('Set SLA error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    return res.status(405).json({ error: 'Method not allowed' });
});
