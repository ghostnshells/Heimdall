// GET/PUT /api/lifecycle/status — Get or update vulnerability status

import { requireAuth } from '../lib/authMiddleware.js';
import { getVulnStatus, setVulnStatus } from '../lib/lifecycleService.js';

export default requireAuth(async function handler(req, res) {
    const { cveId } = req.query;

    if (!cveId) {
        return res.status(400).json({ error: 'cveId query parameter is required' });
    }

    const userId = req.user.email;

    if (req.method === 'GET') {
        try {
            const status = await getVulnStatus(userId, cveId);
            return res.json({ success: true, data: status });
        } catch (error) {
            console.error('Get status error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    if (req.method === 'PUT') {
        try {
            const { status, notes } = req.body || {};

            if (!status) {
                return res.status(400).json({ error: 'status is required' });
            }

            const result = await setVulnStatus(userId, cveId, status, notes || '');
            return res.json({ success: true, data: result });
        } catch (error) {
            if (error.message.includes('Invalid status')) {
                return res.status(400).json({ error: error.message });
            }
            console.error('Set status error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    return res.status(405).json({ error: 'Method not allowed' });
});
