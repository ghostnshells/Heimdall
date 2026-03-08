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
            const { critical, high, medium, low } = req.body || {};
            const fields = { critical, high, medium, low };
            for (const [key, val] of Object.entries(fields)) {
                if (val !== undefined && (typeof val !== 'number' || val < 1 || val > 365)) {
                    return res.status(400).json({ error: `${key} must be a number between 1 and 365` });
                }
            }
            const result = await setSLAConfig(userId, fields);
            return res.json({ success: true, data: result });
        } catch (error) {
            console.error('Set SLA error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    return res.status(405).json({ error: 'Method not allowed' });
});
